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
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <pthread.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

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

	/* Well-formed UTF-8 passes through: 2-, 3- and 4-byte forms. */
	oe_buf_init(&b);
	oe_buf_appendjson(&b, "caf\xc3\xa9 \xe2\x80\x94 \xf0\x9f\x98\x80 \x7f");
	ATF_REQUIRE_STREQ("caf\xc3\xa9 \xe2\x80\x94 \xf0\x9f\x98\x80 \x7f",
	    b.data);
	oe_buf_free(&b);

	/*
	 * Malformed bytes each become U+FFFD: a stray continuation,
	 * truncated sequences, overlong forms, a surrogate, a code
	 * point above U+10FFFF and bytes that never start a sequence.
	 */
	oe_buf_init(&b);
	oe_buf_appendjson(&b, "a\x80" "b\xc3" "c\xe2\x80" "d\xc0\xaf\xe0\x80\xaf"
	    "\xed\xa0\x80\xf4\x90\x80\x80\xfe\xff\xf0\x9f\x98");
	ATF_REQUIRE_STREQ("a\xef\xbf\xbd" "b\xef\xbf\xbd" "c\xef\xbf\xbd"
	    "\xef\xbf\xbd" "d"
	    "\xef\xbf\xbd\xef\xbf\xbd"			/* c0 af */
	    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd"		/* e0 80 af */
	    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd"		/* ed a0 80 */
	    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" /* f4 90.. */
	    "\xef\xbf\xbd\xef\xbf\xbd"			/* fe ff */
	    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd",		/* f0 9f 98 */
	    b.data);
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
	/* No severity member unless one is set. */
	ATF_REQUIRE(strstr(out, "\"severity\"") == NULL);
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
		/*
		 * "/" as the directory is accepted at open time; creating
		 * the file there fails, except for root.
		 */
		if (geteuid() != 0) {
			sc.path = "/nonexistent-otel-test-file";
			sc.durable = 0;
			ATF_REQUIRE(oe_sink_open(&sc) == NULL);
		}
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
		{ 503, "Retry-After: 0\r\n", "busy", 0, 0, 0, 0 },
		{ 200, NULL, "{\"partialSuccess\":{\"rejectedLogRecords\":"
		    " \"3\"}}", 0, 0, 0, 0 },
		/* non-retryable: dropped at once */
		{ 400, NULL, "bad", 0, 0, 0, 0 },
		/* retries exhausted */
		{ 429, NULL, "", 0, 0, 0, 0 },
		{ 502, NULL, "", 0, 0, 0, 0 },
		/* no answer, then garbage, then an unterminated header */
		{ 0, NULL, NULL, 0, 0, 0, 0 },
		{ 200, NULL, NULL, 1, 0, 0, 0 },
		{ 200, NULL, NULL, 0, 1, 0, 0 },
		/* partial success with metrics / spans keys and none */
		{ 200, NULL, "{\"partialSuccess\":{\"rejectedDataPoints\":2}}",
		    0, 0, 0, 0 },
		{ 200, NULL, "{\"partialSuccess\":{}}", 0, 0, 0, 0 },
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
		{ 200, NULL, "{}", 0, 0, 0, 0 },	/* new batch */
		{ 200, NULL, "{}", 0, 0, 0, 0 },	/* spooled line 1 */
		{ 503, NULL, "", 0, 0, 0, 0 },	/* spooled line 2 fails */
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
	/* An empty spool is never replayed while idle. */
	e = otlp_to(port, "http", "empty.jsonl", 0, 0, NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	usleep(400000);
	oe_shutdown(e);
	oe_exporter_free(e);
	e = otlp_to(port, "http", "idle.jsonl", 0, 0, NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	/*
	 * Still down: the first idle tick tries a replay, the next ones
	 * wait out the five-second cadence.
	 */
	ATF_REQUIRE_EQ(0, oe_start(e));
	usleep(1200000);
	ATF_REQUIRE_EQ(0, coll_start(&co, port, 0, NULL));
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
		{ 200, NULL, "{}", 0, 0, 0, 0 },
		{ 200, NULL, "{}", 0, 0, 0, 0 },
		{ 503, NULL, "", 0, 0, 0, 0 },
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
	for (i = 1; i <= 120; i++) {
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


/* ---------------------------------------------------------------- */
/* Spans								*/

static const uint8_t test_salt[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16 };

static struct oe_kv span_attrs[] = {
	{ .key = "net.peer.port", .type = OE_VAL_INT, .i = 443 },
	{ .key = "op", .type = OE_VAL_STRING, .s = "aio_read" },
	{ .key = "ok", .type = OE_VAL_BOOL, .i = 1 },
	{ .key = "ratio", .type = OE_VAL_DOUBLE, .d = 0.5 },
	{ .key = "nil", .type = OE_VAL_STRING, .s = NULL },
};

/* A root span and an erroring child, with fixed ids and times. */
static void
make_spans(struct oe_span *root, struct oe_span *child)
{
	int64_t k;
	int i;

	memset(root, 0, sizeof(*root));
	root->name = "accept";
	root->profile = "test-prof";
	root->probe = "syscall::accept:return";
	root->start.tv_sec = 1700000000;
	root->start.tv_nsec = 1000;
	root->end.tv_sec = 1700000000;
	root->end.tv_nsec = 501000;
	for (i = 0; i < OE_TRACE_ID_LEN; i++)
		root->trace_id[i] = (uint8_t)(0x10 + i);
	for (i = 0; i < OE_SPAN_ID_LEN; i++)
		root->span_id[i] = (uint8_t)(0xa0 + i);
	root->kind = OE_SPAN_SERVER;
	root->pid = 42;
	root->execname = "nginx";
	root->attrs = span_attrs;
	root->nattrs = nitems(span_attrs);
	*child = *root;
	child->name = "read \"data\"";
	child->probe = "";
	child->execname = "";
	child->pid = 0;
	child->kind = OE_SPAN_INTERNAL;
	child->status = OE_STATUS_ERROR;
	child->status_message = "errno 5";
	memcpy(child->parent_span_id, root->span_id, OE_SPAN_ID_LEN);
	k = 7;
	oe_id_derive(test_salt, "span", &k, 1, child->span_id,
	    OE_SPAN_ID_LEN);
	child->attrs = NULL;
	child->nattrs = 0;
}

ATF_TC_WITHOUT_HEAD(span_ids);
ATF_TC_BODY(span_ids, tc)
{
	uint8_t a[16], b[16], zero[8];
	char hex[33];
	int64_t k[2] = { 1, 2 };
	uint8_t salt2[16];

	oe_id_derive(test_salt, "trace", k, 2, a, 16);
	oe_id_derive(test_salt, "trace", k, 2, b, 16);
	ATF_REQUIRE(memcmp(a, b, 16) == 0);
	/* Namespace, key order and salt all matter. */
	oe_id_derive(test_salt, "span", k, 2, b, 16);
	ATF_REQUIRE(memcmp(a, b, 16) != 0);
	k[0] = 2;
	k[1] = 1;
	oe_id_derive(test_salt, "trace", k, 2, b, 16);
	ATF_REQUIRE(memcmp(a, b, 16) != 0);
	memcpy(salt2, test_salt, 16);
	salt2[0] ^= 1;
	oe_id_derive(salt2, "trace", k, 2, b, 16);
	ATF_REQUIRE(memcmp(a, b, 16) != 0);
	/* Over-long namespaces and tuples are truncated, not overrun. */
	{
		int64_t many[12] = { 0 };

		oe_id_derive(test_salt, "a-namespace-longer-than-thirty-two"
		    "-bytes", many, 12, b, 8);
		ATF_REQUIRE(!oe_id_is_zero(b, 8));
	}
	oe_id_random(a, 16);
	oe_id_random(b, 16);
	ATF_REQUIRE(memcmp(a, b, 16) != 0);
	ATF_REQUIRE(!oe_id_is_zero(a, 16));
	memset(zero, 0, sizeof(zero));
	ATF_REQUIRE(oe_id_is_zero(zero, 8));
	a[0] = 0xab;
	a[1] = 0x01;
	oe_id_hex(a, 2, hex);
	ATF_REQUIRE_STREQ("ab01", hex);
}

ATF_TC_WITHOUT_HEAD(span_otlpjson_golden);
ATF_TC_BODY(span_otlpjson_golden, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_span root, child;
	struct otlp_counts c;
	char *text;

	memset(&sc, 0, sizeof(sc));
	sc.path = "spans.jsonl";
	sink = oe_sink_open(&sc);
	e = otlpjson_on(sink, 0);
	make_spans(&root, &child);
	ATF_REQUIRE_EQ(0, oe_span(e, &child));
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	oe_sink_close(sink);
	text = slurp("spans.jsonl", NULL);
	c = check_otlp_lines(tc, text, "otlpjson-spans.jsonl");
	ATF_REQUIRE_EQ(1, c.requests);
	ATF_REQUIRE_EQ(2, c.spans);
	free(text);
}

ATF_TC_WITHOUT_HEAD(span_doubles);
ATF_TC_BODY(span_doubles, tc)
{
	struct oe_kv kv[3] = {
		{ .key = "nan", .type = OE_VAL_DOUBLE },
		{ .key = "inf", .type = OE_VAL_DOUBLE },
		{ .key = "ninf", .type = OE_VAL_DOUBLE },
	};
	struct oe_span root, child;
	struct oe_exporter *e;
	FILE *fp;
	char *out;
	size_t outlen;

	kv[0].d = 0.0 / 0.0;
	kv[1].d = 1.0 / 0.0;
	kv[2].d = -1.0 / 0.0;
	make_spans(&root, &child);
	root.attrs = kv;
	root.nattrs = 3;
	fp = open_memstream(&out, &outlen);
	{
		struct oe_sink_config sc;
		struct oe_sink *sink;

		memset(&sc, 0, sizeof(sc));
		sc.fp = fp;
		sink = oe_sink_open(&sc);
		e = otlpjson_on(sink, 1);
		ATF_REQUIRE_EQ(0, oe_span(e, &root));
		oe_exporter_free(e);
		oe_sink_close(sink);
	}
	fflush(fp);
	check_otlp_lines(tc, out, NULL);
	ATF_REQUIRE(strstr(out, "{\"doubleValue\":\"NaN\"}") != NULL);
	ATF_REQUIRE(strstr(out, "{\"doubleValue\":\"Infinity\"}") != NULL);
	ATF_REQUIRE(strstr(out, "{\"doubleValue\":\"-Infinity\"}") != NULL);
	fclose(fp);
	free(out);
	/* JSONL writes them as null. */
	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "p");
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "\"nan\":null,\"inf\":null,\"ninf\":null") !=
	    NULL);
	free(out);
}

ATF_TC_WITHOUT_HEAD(span_jsonl_text);
ATF_TC_BODY(span_jsonl_text, tc)
{
	struct oe_exporter *e;
	struct oe_span root, child;
	FILE *fp;
	char *out;
	size_t outlen;

	make_spans(&root, &child);
	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "p");
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	child.kind = OE_SPAN_CLIENT;
	ATF_REQUIRE_EQ(0, oe_span(e, &child));
	child.kind = OE_SPAN_PRODUCER;
	child.status_message = NULL;
	ATF_REQUIRE_EQ(0, oe_span(e, &child));
	child.kind = OE_SPAN_CONSUMER;
	ATF_REQUIRE_EQ(0, oe_span(e, &child));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "{\"time\":\"2023-11-14T22:13:20.000Z\","
	    "\"type\":\"span\",\"profile\":\"test-prof\",\"name\":\"accept\","
	    "\"trace_id\":\"101112131415161718191a1b1c1d1e1f\","
	    "\"span_id\":\"a0a1a2a3a4a5a6a7\",\"end\":"
	    "\"2023-11-14T22:13:20.000Z\",\"duration_ns\":500000,"
	    "\"kind\":\"server\",\"status\":\"unset\","
	    "\"probe\":\"syscall::accept:return\",\"attributes\":{"
	    "\"process.pid\":42,\"process.executable.name\":\"nginx\","
	    "\"net.peer.port\":443,\"op\":\"aio_read\",\"ok\":true,"
	    "\"ratio\":0.5,\"nil\":\"\"}}\n") != NULL);
	ATF_REQUIRE(strstr(out, "\"parent_span_id\":\"a0a1a2a3a4a5a6a7\"") !=
	    NULL);
	ATF_REQUIRE(strstr(out, "\"kind\":\"client\",\"status\":\"error\","
	    "\"status_message\":\"errno 5\",\"attributes\":{}}") != NULL);
	ATF_REQUIRE(strstr(out, "\"kind\":\"producer\"") != NULL);
	ATF_REQUIRE(strstr(out, "\"kind\":\"consumer\"") != NULL);
	free(out);

	fp = open_memstream(&out, &outlen);
	e = oe_text_new(fp);
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	ATF_REQUIRE_EQ(0, oe_span(e, &child));
	child.status_message = "boom";
	ATF_REQUIRE_EQ(0, oe_span(e, &child));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "span accept 500us trace=101112131415161718"
	    "191a1b1c1d1e1f span=a0a1a2a3a4a5a6a7\n") != NULL);
	ATF_REQUIRE(strstr(out, "span read \"data\" 500us error trace=") !=
	    NULL);
	ATF_REQUIRE(strstr(out, " error: boom trace=") != NULL);
	ATF_REQUIRE(strstr(out, " parent=a0a1a2a3a4a5a6a7\n") != NULL);
	free(out);

	/* Collapsed ignores spans; failures propagate elsewhere. */
	fp = open_memstream(&out, &outlen);
	e = oe_collapsed_new(fp);
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	oe_exporter_free(e);
	fclose(fp);
	free(out);
	fp = fwopen(NULL, enospc_write);
	setvbuf(fp, NULL, _IONBF, 0);
	e = oe_jsonl_new(fp, "p");
	ATF_REQUIRE_EQ(-1, oe_span(e, &root));
	oe_exporter_free(e);
	e = oe_text_new(fp);
	ATF_REQUIRE_EQ(-1, oe_span(e, &root));
	oe_exporter_free(e);
	fclose(fp);
}

ATF_TC_WITHOUT_HEAD(span_http);
ATF_TC_BODY(span_http, tc)
{
	static const struct coll_reply script[] = {
		{ 200, NULL, "{\"partialSuccess\":{\"rejectedSpans\":\"1\"}}",
		    0, 0, 0, 0 },
	};
	struct collector co;
	struct oe_exporter *e;
	struct oe_span root, child;
	struct otlp_counts c;
	int i;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	coll_script(&co, script, nitems(script));
	e = otlp_to(co.port, "http", NULL, 0, 0, NULL);
	make_spans(&root, &child);
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	ATF_REQUIRE_EQ(0, oe_span(e, &child));	/* batch of 2: queued */
	ATF_REQUIRE_EQ(0, oe_start(e));
	ATF_REQUIRE_EQ(0, coll_wait(&co, 1, 3000));
	ATF_REQUIRE_STREQ("/base/v1/traces", co.reqs[0].path);
	c = check_otlp_lines(tc, co.reqs[0].body, NULL);
	ATF_REQUIRE_EQ(2, c.spans);
	oe_shutdown(e);
	oe_exporter_free(e);
	/* Allocation failure while encoding spans. */
	for (i = 1; i <= 12; i++) {
		e = otlp_to(co.port, "http", NULL, 0, 0, NULL);
		failalloc_arm(i);
		(void)oe_span(e, &root);
		failalloc_arm(0);
		oe_shutdown(e);
		oe_exporter_free(e);
	}
	coll_stop(&co);
}

/*
 * The validator is the oracle, so it is tested too: each document
 * breaks one OTLP or JSON rule and must be rejected for that reason.
 */
ATF_TC_WITHOUT_HEAD(validator_rejects);
ATF_TC_BODY(validator_rejects, tc)
{
	static const struct {
		const char *doc, *why;
	} cases[] = {
		{ "{\"resourceLogs\":[],}", "trailing comma" },
		{ "{\"resourceLogs\":[]", "expected ','" },
		{ "{\"a\":1,\"a\":2}", "duplicate key" },
		{ "{\"resourceLogs\":[]} x", "trailing data" },
		{ "\"\\x\"", "invalid escape" },
		{ "\"\\ud800\"", "unpaired high surrogate" },
		{ "\"\\udc00\"", "lone low surrogate" },
		{ "\"\xc3\"", "invalid UTF-8" },
		{ "\"\xe0\x80\x80\"", "invalid UTF-8" },
		{ "\"a\x01\"", "raw control" },
		{ "01", "leading zero" },
		{ "1.", "bad fraction" },
		{ "1e", "bad exponent" },
		{ "-", "bad number" },
		{ "nul", "invalid literal" },
		{ "{\"x\":{}}", "unknown request type" },
		{ "{\"resourceLogs\":[],\"resourceSpans\":[]}",
		    "exactly one top-level" },
		{ "{\"resourceLogs\":[{\"bogus\":1}]}",
		    "unknown ResourceLogs field" },
		{ "{\"resourceLogs\":{}}", "must be an array" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"timeUnixNano\":1}]}]}]}", "decimal string" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"timeUnixNano\":\"-1\"}]}]}]}", "decimal string" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"timeUnixNano\":\"99999999999999999999\"}]}]}]}",
		    "decimal string" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"severityNumber\":25}]}]}]}", "out of range" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"severityNumber\":\"9\"}]}]}]}", "non-negative integer" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"body\":{\"stringValue\":\"a\",\"intValue\":\"1\"}}]}]}]}",
		    "AnyValue has 2" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"body\":{\"intValue\":1}}]}]}]}", "decimal string" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"body\":{\"bytesValue\":\"abc\"}}]}]}]}", "base64" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"body\":{\"fooValue\":1}}]}]}]}", "unknown AnyValue" },
		{ "{\"resourceLogs\":[{\"resource\":{\"attributes\":["
		    "{\"key\":\"a\",\"value\":{}},{\"key\":\"a\",\"value\":{}}"
		    "]}}]}", "duplicate attribute key" },
		{ "{\"resourceLogs\":[{\"resource\":{\"attributes\":["
		    "{\"key\":\"\",\"value\":{}}]}}]}", "has no key" },
		{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"traceId\":\"ABCDEF0123456789ABCDEF0123456789\"}]}]}]}",
		    "lowercase hex" },
		{ "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{"
		    "\"name\":\"m\"}]}]}]}", "has no data" },
		{ "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{"
		    "\"name\":\"m\",\"gauge\":{},\"sum\":{}}]}]}]}",
		    "more than one member of oneof" },
		{ "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":["
		    "{\"name\":\"m\",\"gauge\":{}},{\"name\":\"m\",\"sum\":{}}"
		    "]}]}]}", "is both gauge and sum" },
		{ "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{"
		    "\"name\":\"m\",\"gauge\":{\"dataPoints\":[{"
		    "\"timeUnixNano\":\"1\"}]}}]}]}]}", "no value" },
		{ "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{"
		    "\"name\":\"m\",\"histogram\":{\"dataPoints\":[{"
		    "\"timeUnixNano\":\"1\",\"count\":\"3\",\"bucketCounts\":"
		    "[\"1\",\"1\"],\"explicitBounds\":[1]}]}}]}]}]}",
		    "count 3 != sum" },
		{ "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{"
		    "\"name\":\"m\",\"histogram\":{\"dataPoints\":[{"
		    "\"timeUnixNano\":\"1\",\"count\":\"2\",\"bucketCounts\":"
		    "[\"1\",\"1\"],\"explicitBounds\":[]}]}}]}]}]}",
		    "need 1 explicitBounds" },
		{ "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{"
		    "\"name\":\"m\",\"histogram\":{\"dataPoints\":[{"
		    "\"timeUnixNano\":\"1\",\"count\":\"3\",\"bucketCounts\":"
		    "[\"1\",\"1\",\"1\"],\"explicitBounds\":[2,1]}]}}]}]}]}",
		    "strictly increasing" },
		{ "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{"
		    "\"spanId\":\"0102030405060708\",\"name\":\"s\"}]}]}]}",
		    "no traceId" },
		{ "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{"
		    "\"traceId\":\"00000000000000000000000000000000\"}]}]}]}",
		    "non-zero" },
		{ "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{"
		    "\"traceId\":\"0102030405060708090a0b0c0d0e0f10\","
		    "\"spanId\":\"0102030405060708\",\"parentSpanId\":"
		    "\"0102030405060708\",\"name\":\"s\"}]}]}]}",
		    "own parent" },
		{ "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{"
		    "\"traceId\":\"0102030405060708090a0b0c0d0e0f10\","
		    "\"spanId\":\"0102030405060708\",\"name\":\"s\","
		    "\"startTimeUnixNano\":\"2\",\"endTimeUnixNano\":\"1\"}]}]}]}",
		    "ends before it starts" },
		{ "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{"
		    "\"traceId\":\"0102030405060708090a0b0c0d0e0f10\","
		    "\"spanId\":\"0102030405060708\",\"name\":\"s\","
		    "\"kind\":6}]}]}]}", "out of range" },
		{ "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{"
		    "\"traceId\":\"0102030405060708090a0b0c0d0e0f10\","
		    "\"spanId\":\"0102030405060708\",\"name\":\"\"}]}]}]}",
		    "no name" },
	};
	struct jv *v;
	char err[512];
	size_t i;
	int rc;

	for (i = 0; i < nitems(cases); i++) {
		v = jv_parse(cases[i].doc, strlen(cases[i].doc), err,
		    sizeof(err));
		if (v != NULL) {
			rc = otlp_validate_request(v, NULL, err, sizeof(err));
			jv_free(v);
			ATF_REQUIRE_MSG(rc != 0, "accepted: %s", cases[i].doc);
		}
		ATF_REQUIRE_MSG(strstr(err, cases[i].why) != NULL,
		    "%s: got \"%s\", want \"%s\"", cases[i].doc, err,
		    cases[i].why);
	}
}

/* And it accepts what the spec allows that this library never emits. */
ATF_TC_WITHOUT_HEAD(validator_accepts);
ATF_TC_BODY(validator_accepts, tc)
{
	static const char *const docs[] = {
		"{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{"
		    "\"body\":{\"arrayValue\":{\"values\":[{\"doubleValue\":1.5},"
		    "{\"boolValue\":false},{\"doubleValue\":\"NaN\"}]}},"
		    "\"attributes\":[{\"key\":\"k\",\"value\":{\"kvlistValue\":"
		    "{\"values\":[{\"key\":\"x\",\"value\":{\"bytesValue\":"
		    "\"AAE=\"}}]}}}],\"flags\":1,\"traceId\":\"\","
		    "\"spanId\":\"\",\"eventName\":\"e\"}]}]}]}",
		" {\"resourceMetrics\" : [ ] } ",
		"{\"resourceSpans\":[{\"resource\":{\"attributes\":[],"
		    "\"droppedAttributesCount\":0},\"scopeSpans\":[{\"scope\":{"
		    "\"name\":\"s\"},\"spans\":[{\"traceId\":"
		    "\"0102030405060708090a0b0c0d0e0f10\",\"spanId\":"
		    "\"0102030405060708\",\"name\":\"s\",\"startTimeUnixNano\":"
		    "\"1\",\"endTimeUnixNano\":\"1\",\"events\":[{\"name\":\"e\","
		    "\"timeUnixNano\":\"1\"}],\"links\":[{\"traceId\":"
		    "\"0102030405060708090a0b0c0d0e0f10\",\"spanId\":"
		    "\"0102030405060709\"}],\"status\":{}}]}]}]}",
		"{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{\"body\":"
		    "{\"stringValue\":\"\\u00e9\\ud83d\\ude00\\/\\b\\f\\n\\r\\t\"}"
		    "}]}]}]}",
		"{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{"
		    "\"name\":\"m\",\"gauge\":{\"dataPoints\":[{"
		    "\"timeUnixNano\":\"1\",\"asDouble\":-1.5e-3}]}}]}]}]}",
	};
	struct jv *v;
	char err[512];
	size_t i;

	for (i = 0; i < nitems(docs); i++) {
		v = jv_parse(docs[i], strlen(docs[i]), err, sizeof(err));
		ATF_REQUIRE_MSG(v != NULL, "%s: %s", docs[i], err);
		ATF_REQUIRE_MSG(otlp_validate_request(v, NULL, err,
		    sizeof(err)) == 0, "%s: %s", docs[i], err);
		jv_free(v);
	}
}

/* ---------------------------------------------------------------- */
/* Semantic conventions						 	*/

static struct oe_context
full_context(void)
{
	struct oe_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.flags = OE_CTX_PPID | OE_CTX_TID | OE_CTX_UID | OE_CTX_RUID |
	    OE_CTX_GID | OE_CTX_RGID | OE_CTX_CPU | OE_CTX_JAIL | OE_CTX_PID;
	ctx.ppid = 1;
	ctx.tid = 100123;
	ctx.uid = 80;
	ctx.ruid = 1001;
	ctx.gid = 80;
	ctx.rgid = 1001;
	ctx.cpu = 3;
	ctx.jid = 5;
	ctx.jail_name = "web";
	return (ctx);
}

/*
 * Logs, spans and metrics name the same things the same way: the
 * golden is built independently (gen_golden_s3.py) from the
 * conventions, and resource overrides replace detected values.
 */
ATF_TC_WITHOUT_HEAD(semconv_golden);
ATF_TC_BODY(semconv_golden, tc)
{
	static const struct oe_attr custom[] = {
		{ "host.name", "override" },
		{ "deployment.environment.name", "lab" },
		{ "service.name", "ignored" },
		{ "team", "a" },
		{ "team", "b" },
	};
	static struct oe_attr dims[] = {
		{ "process.pid", "123" },
		{ "thread.id", "notanumber" },
		{ "cpu.logical_number", "" },
		{ "process.executable.name", "nginx" },
	};
	struct oe_resource res;
	struct oe_otlpjson_config cfg;
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_span root, child;
	struct oe_snapshot sn;
	struct oe_datapoint dp;
	struct otlp_counts c;
	char *text;

	res = test_resource;
	res.host_id = "0123-hostuuid";
	res.os_full_name = "FreeBSD";
	res.os_description = "FreeBSD 16.0-CURRENT GENERIC";
	res.service_instance_id = "8f6c1f4e-5b1d-4c2a-9a3e-0d9f2b7c6a11";
	res.custom = custom;
	res.ncustom = nitems(custom);
	memset(&sc, 0, sizeof(sc));
	sc.path = "semconv.jsonl";
	sink = oe_sink_open(&sc);
	memset(&cfg, 0, sizeof(cfg));
	cfg.sink = sink;
	cfg.resource = &res;
	e = oe_otlpjson_new(&cfg);
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	fixed_event_times(&ev);
	ev.nstack = ev.nustack = 0;
	ev.ctx = full_context();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	/* The host (jid 0) is not a container; pid 0 known is kept. */
	ev.ctx.jid = 0;
	ev.pid = 0;
	ev.execname = "";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	/* Unknown pid and no context: no process attributes at all. */
	memset(&ev.ctx, 0, sizeof(ev.ctx));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	make_spans(&root, &child);
	root.attrs = NULL;
	root.nattrs = 0;
	root.ctx = full_context();
	root.ctx.jail_name = NULL;
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	memset(&dp, 0, sizeof(dp));
	dp.attrs = dims;
	dp.nattrs = nitems(dims);
	dp.scalar = 9;
	memset(&sn, 0, sizeof(sn));
	sn.ts.tv_sec = 1700000010;
	sn.profile = "test-prof";
	sn.name = "calls";
	sn.kind = OE_AGG_COUNT;
	sn.points = &dp;
	sn.npoints = 1;
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	oe_sink_close(sink);
	text = slurp("semconv.jsonl", NULL);
	c = check_otlp_lines(tc, text, "otlpjson-semconv.jsonl");
	ATF_REQUIRE_EQ(3, c.requests);
	free(text);
}

ATF_TC_WITHOUT_HEAD(semconv_jsonl);
ATF_TC_BODY(semconv_jsonl, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "p");
	ev = make_event();
	ev.nstack = ev.nustack = 0;
	ev.ctx = full_context();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE_MSG(strstr(out, "\"attributes\":{\"process.pid\":123,"
	    "\"process.parent_pid\":1,\"process.executable.name\":\"nginx\","
	    "\"process.user.id\":80,\"process.real_user.id\":1001,"
	    "\"process.group.id\":80,\"process.real_group.id\":1001,"
	    "\"thread.id\":100123,\"cpu.logical_number\":3,"
	    "\"container.id\":\"5\",\"container.name\":\"web\","
	    "\"container.runtime.name\":\"jail\"}}\n") != NULL, "%s", out);
	free(out);
}

ATF_TC_WITHOUT_HEAD(host_detection);
ATF_TC_BODY(host_detection, tc)
{
	static const char *const map[][2] = {
		{ "amd64", "amd64" }, { "aarch64", "arm64" }, { "i386", "x86" },
		{ "powerpc64", "ppc64" }, { "powerpc64le", "ppc64" },
		{ "powerpc", "ppc32" }, { "armv6", "arm32" },
		{ "armv7", "arm32" }, { "riscv64", "riscv64" },
	};
	struct oe_host_info hi, hi2;
	struct oe_resource r;
	char buf[32];
	size_t i;

	for (i = 0; i < nitems(map); i++) {
		oe_host_arch_semconv(map[i][0], buf, sizeof(buf));
		ATF_REQUIRE_STREQ(map[i][1], buf);
	}
	oe_host_detect(&hi);
	ATF_REQUIRE(hi.host_name[0] != '\0');
	ATF_REQUIRE_STREQ("freebsd", hi.os_type);
	ATF_REQUIRE(hi.os_name[0] != '\0');
	ATF_REQUIRE(strncmp(hi.os_description, hi.os_name,
	    strlen(hi.os_name)) == 0);
	/* UUID version 4, variant 10xx. */
	ATF_REQUIRE_EQ(36, strlen(hi.instance_id));
	ATF_REQUIRE_EQ('4', hi.instance_id[14]);
	ATF_REQUIRE(strchr("89ab", hi.instance_id[19]) != NULL);
	oe_host_detect(&hi2);
	ATF_REQUIRE(strcmp(hi.instance_id, hi2.instance_id) != 0);
	memset(&r, 0, sizeof(r));
	oe_resource_host(&r, &hi);
	ATF_REQUIRE(r.host_name == hi.host_name);
	ATF_REQUIRE(r.service_instance_id == hi.instance_id);
	ATF_REQUIRE_STREQ("freebsd", r.os_name);
	/* Unknown values are omitted rather than exported empty. */
	hi.host_id[0] = hi.os_name[0] = hi.os_description[0] = '\0';
	oe_resource_host(&r, &hi);
	ATF_REQUIRE(r.host_id == NULL && r.os_full_name == NULL &&
	    r.os_description == NULL);
}

/*
 * UTF-8 in every format: valid text survives byte for byte and
 * malformed input still yields documents the independent validator
 * (which checks UTF-8) accepts.
 */
ATF_TC_WITHOUT_HEAD(utf8_all_formats);
ATF_TC_BODY(utf8_all_formats, tc)
{
	static const char *const bodies[] = {
		"r\xc3\xa9sum\xc3\xa9 \xe2\x80\x94 \xf0\x9f\x98\x80",
		"trunc\xe2\x80", "overlong\xc0\xaf", "bad\xff",
	};
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_span root, child;
	struct jv *v;
	char *out, *line, *last, err[256];
	size_t outlen, i;
	FILE *fp;

	ev = make_event();
	make_spans(&root, &child);
	/* OTLP JSON Lines. */
	fp = open_memstream(&out, &outlen);
	memset(&sc, 0, sizeof(sc));
	sc.fp = fp;
	sink = oe_sink_open(&sc);
	e = otlpjson_on(sink, 0);
	for (i = 0; i < nitems(bodies); i++) {
		ev.body = bodies[i];
		ev.execname = bodies[i];
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		root.name = bodies[i];
		ATF_REQUIRE_EQ(0, oe_span(e, &root));
	}
	ATF_REQUIRE_EQ(0, oe_flush(e));
	oe_exporter_free(e);
	oe_sink_close(sink);
	fclose(fp);
	check_otlp_lines(tc, out, NULL);
	ATF_REQUIRE(strstr(out, bodies[0]) != NULL);
	ATF_REQUIRE(strstr(out, "trunc\xef\xbf\xbd\xef\xbf\xbd") != NULL);
	free(out);
	/* JSON Lines: every line parses as strict JSON. */
	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "p\xc3\xa9");
	for (i = 0; i < nitems(bodies); i++) {
		ev.body = bodies[i];
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		root.name = bodies[i];
		ATF_REQUIRE_EQ(0, oe_span(e, &root));
	}
	oe_exporter_free(e);
	fclose(fp);
	for (line = strtok_r(out, "\n", &last); line != NULL;
	    line = strtok_r(NULL, "\n", &last)) {
		v = jv_parse(line, strlen(line), err, sizeof(err));
		ATF_REQUIRE_MSG(v != NULL, "%s: %s", line, err);
		jv_free(v);
	}
	free(out);
	/* Text keeps the bytes as they are (not JSON). */
	fp = open_memstream(&out, &outlen);
	e = oe_text_new(fp);
	ev.body = bodies[0];
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strncmp(out, bodies[0], strlen(bodies[0])) == 0);
	free(out);
}


/* ---------------------------------------------------------------- */
/* Edges of every exporter						*/

/* Collapsed: user-only stacks, a NULL execname, bucket collisions. */
ATF_TC_WITHOUT_HEAD(collapsed_edges);
ATF_TC_BODY(collapsed_edges, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	FILE *fp;
	char *out, name[32];
	size_t outlen;
	int i;

	fp = open_memstream(&out, &outlen);
	e = oe_collapsed_new(fp);
	ATF_REQUIRE_EQ(0, oe_start(e));
	sn = make_snapshot(OE_AGG_COUNT, "c");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));		/* ignored */
	ATF_REQUIRE_EQ(0, oe_flush(e));			/* no-op */
	ev = make_event();
	ev.nstack = 0;					/* user stack only */
	ev.execname = NULL;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	/* More distinct stacks than hash buckets: chains form. */
	ev = make_event();
	for (i = 0; i < 5000; i++) {
		snprintf(name, sizeof(name), "p%d", i);
		ev.execname = name;
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	}
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strncmp(out, ";0x00000000deadbeef 1\n", 22) == 0);
	ATF_REQUIRE(strstr(out, "\np4999;kernel`syscall") != NULL);
	free(out);
}

ATF_TC_WITHOUT_HEAD(text_every_kind);
ATF_TC_BODY(text_every_kind, tc)
{
	static struct oe_bucket b[2] = { { 1, 0 }, { 3, 5 } };
	struct oe_exporter *e;
	struct oe_snapshot sn;
	struct oe_datapoint dp;
	enum oe_agg_kind k;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_text_new(fp);
	for (k = OE_AGG_COUNT; k <= OE_AGG_LLQUANTIZE; k++) {
		sn = make_snapshot(k, "a");
		ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	}
	/* Empty histogram buckets are not printed. */
	memset(&dp, 0, sizeof(dp));
	dp.is_histogram = 1;
	dp.buckets = b;
	dp.nbuckets = 2;
	sn.points = &dp;
	sn.npoints = 1;
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	sn.kind = (enum oe_agg_kind)99;			/* defensive */
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "(sum)") && strstr(out, "(min)") &&
	    strstr(out, "(max)") && strstr(out, "(avg)") &&
	    strstr(out, "(stddev)") && strstr(out, "(lquantize)") &&
	    strstr(out, "(llquantize)") && strstr(out, "(unknown)"));
	ATF_REQUIRE(strstr(out, "<= 1: 0") == NULL);
	ATF_REQUIRE(strstr(out, "<= 3: 5") != NULL);
	free(out);
}

/* JSONL with a resource, NULL and partial fields, every value type. */
ATF_TC_WITHOUT_HEAD(jsonl_edges);
ATF_TC_BODY(jsonl_edges, tc)
{
	static const struct oe_attr res[] = {
		{ "hypertrace.vm.name", "vm\"1" }, { "hypertrace.vm.id", "3" },
	};
	struct oe_kv kv[2] = {
		{ .key = "no", .type = OE_VAL_BOOL, .i = 0 },
		{ .key = "s", .type = OE_VAL_STRING, .s = "x" },
	};
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_span root, child;
	FILE *fp;
	char *out;
	size_t outlen;
	int i;

	fp = open_memstream(&out, &outlen);
	memset(&sc, 0, sizeof(sc));
	sc.fp = fp;
	sink = oe_sink_open(&sc);
	e = oe_jsonl_resource_new(sink, NULL, res, nitems(res));
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	ev.probe = NULL;
	ev.observed.tv_nsec = 7;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.body = NULL;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));		/* skipped */
	make_spans(&root, &child);
	root.kind = OE_SPAN_INTERNAL;
	root.probe = NULL;
	root.attrs = kv;
	root.nattrs = 2;
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	oe_exporter_free(e);
	oe_sink_close(sink);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "\"observed\":\"1970-01-01T00:00:00.000Z\"")
	    != NULL);
	ATF_REQUIRE(strstr(out, "\"probe\"") == NULL);
	ATF_REQUIRE(strstr(out, "\"kind\":\"internal\"") != NULL);
	ATF_REQUIRE(strstr(out, "\"no\":false,\"s\":\"x\"") != NULL);
	ATF_REQUIRE(strstr(out, ",\"resource\":{\"hypertrace.vm.name\":"
	    "\"vm\\\"1\",\"hypertrace.vm.id\":\"3\"}}\n") != NULL);
	free(out);
	/* Allocation failures at construction and while writing. */
	fp = open_memstream(&out, &outlen);
	memset(&sc, 0, sizeof(sc));
	sc.fp = fp;
	sink = oe_sink_open(&sc);
	for (i = 1; i <= 30; i++) {
		failalloc_arm(i);
		e = oe_jsonl_resource_new(sink, "p", res, nitems(res));
		failalloc_arm(0);
		if (e == NULL)
			continue;
		failalloc_arm(i);
		(void)oe_span(e, &root);
		failalloc_arm(0);
		oe_exporter_free(e);
	}
	oe_sink_close(sink);
	fclose(fp);
	free(out);
}

/* OTLP encoding edges, checked by the independent validator. */
ATF_TC_WITHOUT_HEAD(otlp_encoding_edges);
ATF_TC_BODY(otlp_encoding_edges, tc)
{
	static struct oe_attr dims[] = {
		{ "process.pid", "99999999999999999999" },
		{ "label", NULL },
		{ "thread.id", NULL },
	};
	static struct oe_bucket none[1];
	struct oe_datapoint dps[3];
	struct oe_otlpjson_config cfg;
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_span root, child;
	struct oe_snapshot sn;
	struct oe_kv kv = { .key = "no", .type = OE_VAL_BOOL, .i = 0 };
	struct otlp_counts c;
	char *text;
	int i;

	memset(&sc, 0, sizeof(sc));
	sc.path = "edges.jsonl";
	sink = oe_sink_open(&sc);
	memset(&cfg, 0, sizeof(cfg));
	cfg.sink = sink;
	cfg.resource = &test_resource;
	cfg.scope_name = "tool";
	cfg.batch_size = 100;
	e = oe_otlpjson_new(&cfg);
	ev = make_event();
	ev.ts.tv_sec = -1;			/* before the epoch: unknown */
	ev.probe = NULL;
	ev.execname = NULL;
	ev.observed.tv_nsec = 1;
	/* More records than the first fragment array holds. */
	for (i = 0; i < 70; i++)
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.body = NULL;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	make_spans(&root, &child);
	root.probe = NULL;
	root.attrs = &kv;
	root.nattrs = 1;
	ATF_REQUIRE_EQ(0, oe_span(e, &root));
	memset(dps, 0, sizeof(dps));
	dps[0].attrs = dims;
	dps[0].nattrs = 3;
	dps[1].attrs = dims;
	dps[1].nattrs = 2;
	dps[2].is_histogram = 1;
	dps[2].buckets = none;
	dps[2].nbuckets = 0;			/* an empty histogram: skipped */
	memset(&sn, 0, sizeof(sn));
	sn.ts.tv_sec = 1;
	sn.profile = "p";
	sn.name = NULL;				/* named after the kind */
	sn.kind = OE_AGG_MIN;
	sn.points = dps;
	sn.npoints = 3;
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	sn.kind = OE_AGG_QUANTIZE;
	sn.name = "h";
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	oe_sink_close(sink);
	text = slurp("edges.jsonl", NULL);
	c = check_otlp_lines(tc, text, NULL);
	ATF_REQUIRE_EQ(70, c.logs);
	ATF_REQUIRE_EQ(1, c.spans);
	ATF_REQUIRE(strstr(text, "\"name\":\"tool\"") != NULL);
	ATF_REQUIRE(strstr(text, "\"timeUnixNano\":\"0\"") != NULL);
	ATF_REQUIRE(strstr(text, "\"name\":\"tool.p.min\"") != NULL);
	ATF_REQUIRE(strstr(text, "{\"key\":\"process.pid\",\"value\":"
	    "{\"stringValue\":\"99999999999999999999\"}}") != NULL);
	ATF_REQUIRE(strstr(text, "{\"key\":\"label\",\"value\":"
	    "{\"stringValue\":\"\"}}") != NULL);
	ATF_REQUIRE(strstr(text, "{\"boolValue\":false}") != NULL);
	free(text);
}

/* Odd HTTP conversations: 1xx and 504 answers, oversized answers, resets. */
ATF_TC_WITHOUT_HEAD(otlp_http_edges);
ATF_TC_BODY(otlp_http_edges, tc)
{
	static const struct coll_reply script[] = {
		{ 199, NULL, "", 0, 0, 0, 0 },		/* not 2xx: rejected */
		{ 504, NULL, "", 0, 0, 0, 0 },		/* retryable... */
		{ 200, NULL, "{\"partialSuccess\":{\"rejectedLogRecords\":"
		    "\t 4}}", 0, 0, 0, 0 },		/* ...then accepted */
		{ 200, NULL, NULL, 0, 0, 0, 100000 },	/* bounded read */
		{ 0, NULL, NULL, 0, 0, 1, 0 },		/* reset at once */
	};
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_otlp_config cfg;
	char url[64], big[200000];

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	coll_script(&co, script, nitems(script));
	ev = make_event();
	e = otlp_to(co.port, "http", NULL, 0, 1, "none");
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* 199 */
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* 504, 200 */
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* oversized answer */
	ATF_REQUIRE_EQ(4, coll_nreqs(&co));
	/* A large body to a peer that resets: no SIGPIPE, a failure. */
	memset(big, 'b', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	ev.body = big;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	oe_shutdown(e);
	oe_exporter_free(e);
	/* Defaults: retries, batch, flush interval, timeout. */
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", co.port);
	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = url;
	cfg.resource = &test_resource;
	cfg.max_retries = -1;
	e = oe_otlp_new(&cfg);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	usleep(700000);			/* an idle tick without a spool */
	ev = make_event();
	ev.body = NULL;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));	/* skipped */
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
	/* Malformed bracketed port. */
	{
		struct oe_url u;

		ATF_REQUIRE_EQ(-1, oe_url_parse("http://[::1]:99999/", &u));
	}
}

/* Two full batches queue two jobs before the sender thread starts. */
ATF_TC_WITHOUT_HEAD(otlp_job_queue);
ATF_TC_BODY(otlp_job_queue, tc)
{
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	int i;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	e = otlp_to(co.port, "http", NULL, 0, 0, NULL);
	ev = make_event();
	for (i = 0; i < 4; i++)
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_start(e));
	ATF_REQUIRE_EQ(0, coll_wait(&co, 2, 3000));
	oe_shutdown(e);
	/* Jobs never sent (no start) are released by free. */
	oe_exporter_free(e);
	e = otlp_to(co.port, "http", NULL, 0, 0, NULL);
	for (i = 0; i < 4; i++)
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_exporter_free(e);
	coll_stop(&co);
}

/*
 * Spool corner cases: a replay whose first line fails, one that only
 * removes garbage, exactly one dropped batch, a spool that vanished.
 */
ATF_TC_WITHOUT_HEAD(otlp_spool_edges);
ATF_TC_BODY(otlp_spool_edges, tc)
{
	static const struct coll_reply firstfails[] = {
		{ 200, NULL, "{}", 0, 0, 0, 0 },
		{ 503, NULL, "", 0, 0, 0, 0 },
	};
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct stat st;
	FILE *fp;
	int port, i;

	ev = make_event();
	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	/* First replayed line refused: nothing removed. */
	fp = fopen("a.jsonl", "w");
	fprintf(fp, "{\"resourceLogs\":[]}\n");
	fclose(fp);
	coll_script(&co, firstfails, nitems(firstfails));
	e = otlp_to(co.port, "http", "a.jsonl", 0, 0, NULL);
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE(stat("a.jsonl", &st) == 0 && st.st_size == 20);
	oe_shutdown(e);
	oe_exporter_free(e);
	/* Only garbage: removed, nothing resent. */
	fp = fopen("b.jsonl", "w");
	fprintf(fp, "garbage\n");
	fclose(fp);
	coll_script(&co, NULL, 0);
	e = otlp_to(co.port, "http", "b.jsonl", 0, 0, NULL);
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE(stat("b.jsonl", &st) == 0 && st.st_size == 0);
	/* The spool vanished between the outage and the replay. */
	fp = fopen("b.jsonl", "w");
	fprintf(fp, "{\"resourceLogs\":[]}\n");
	fclose(fp);
	oe_shutdown(e);
	oe_exporter_free(e);
	e = otlp_to(co.port, "http", "b.jsonl", 0, 0, NULL);
	ATF_REQUIRE_EQ(0, unlink("b.jsonl"));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
	/* Exactly one batch dropped, then drained. */
	port = closed_port();
	e = otlp_to(port, "http", "c.jsonl", 2000, 0, NULL);
	for (i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		ATF_REQUIRE_EQ(0, oe_flush(e));
	}
	ATF_REQUIRE_EQ(0, coll_start(&co, port, 0, NULL));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
	/* Allocation failure reading the spool for a replay. */
	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	for (i = 1; i <= 80; i++) {
		fp = fopen("d.jsonl", "w");
		fprintf(fp, "{\"resourceLogs\":[]}\n");
		fclose(fp);
		e = otlp_to(co.port, "http", "d.jsonl", 0, 0, NULL);
		failalloc_arm(i);
		(void)oe_event(e, &ev);
		(void)oe_flush(e);
		failalloc_arm(0);
		oe_shutdown(e);
		oe_exporter_free(e);
	}
	coll_stop(&co);
}

/* Sinks: a borrowed stream ignores age rotation; polls below limits. */
ATF_TC_WITHOUT_HEAD(sink_edges);
ATF_TC_BODY(sink_edges, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	memset(&sc, 0, sizeof(sc));
	sc.fp = fp;
	sc.rotate_interval = 1;
	s = oe_sink_open(&sc);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "a\n", 2));
	sleep(1);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "b\n", 2));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	fclose(fp);
	ATF_REQUIRE_STREQ("a\nb\n", out);
	free(out);
	memset(&sc, 0, sizeof(sc));
	sc.path = "p.log";
	sc.rotate_size = 100;
	s = oe_sink_open(&sc);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "small\n", 6));
	ATF_REQUIRE_EQ(0, oe_sink_poll(s));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
}

/* UTF-8 boundaries and environment odds. */
ATF_TC_WITHOUT_HEAD(util_edges);
ATF_TC_BODY(util_edges, tc)
{
	struct oe_buf b;
	struct oe_env env;
	struct oe_frame f;
	char buf[64];

	oe_buf_init(&b);
	/* Overlong four-byte form of U+FFFF. */
	oe_buf_appendjson(&b, "\xf0\x8f\xbf\xbf");
	ATF_REQUIRE_STREQ("\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd",
	    b.data);
	oe_buf_free(&b);
	/* Size overflow and a format error poison the buffer. */
	oe_buf_init(&b);
	ATF_REQUIRE_EQ(-1, oe_buf_append(&b, "x", SIZE_MAX));
	ATF_REQUIRE_EQ(1, b.error);
	oe_buf_free(&b);
	oe_buf_init(&b);
	ATF_REQUIRE_EQ(-1, oe_buf_appendf(&b, "%ls", L"\xd800"));
	oe_buf_free(&b);
	/* Blank-only entries, tabs, DEL in a header, huge timeouts. */
	setenv("OTEL_RESOURCE_ATTRIBUTES", "\t , a\t=\tb ,", 1);
	setenv("OTEL_EXPORTER_OTLP_HEADERS", "X=a\x7f", 1);
	setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "3000000000", 1);
	oe_env_load(&env);
	ATF_REQUIRE_EQ(1, env.nresource_attrs);
	ATF_REQUIRE_STREQ("b", env.resource_attrs[0].value);
	ATF_REQUIRE_EQ(0, env.nheaders);
	ATF_REQUIRE_EQ(-1, env.timeout_ms);
	oe_env_free(&env);
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
	unsetenv("OTEL_EXPORTER_OTLP_HEADERS");
	unsetenv("OTEL_EXPORTER_OTLP_TIMEOUT");
	/* A frame with a module but no symbol prints its address. */
	memset(&f, 0, sizeof(f));
	f.module = __DECONST(char *, "kernel");
	f.addr = 0x10;
	oe_frame_format(&f, buf, sizeof(buf));
	ATF_REQUIRE_STREQ("0x0000000000000010", buf);
	/* The legacy host helpers. */
	oe_host_arch(buf, sizeof(buf));
	ATF_REQUIRE(buf[0] != '\0');
	oe_os_version(buf, sizeof(buf));
	ATF_REQUIRE(buf[0] != '\0');
	oe_host_name(buf, sizeof(buf));
	ATF_REQUIRE(buf[0] != '\0');
}

/* Allocation-failure sweeps long enough to reach every path. */
ATF_TC(alloc_sweeps);
ATF_TC_HEAD(alloc_sweeps, tc)
{

	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(alloc_sweeps, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_span root, child;
	struct oe_snapshot sn;
	struct oe_otlpjson_config cfg;
	int i;

	ev = make_event();
	make_spans(&root, &child);
	memset(&sc, 0, sizeof(sc));
	sc.path = "sweep.jsonl";
	sink = oe_sink_open(&sc);
	memset(&cfg, 0, sizeof(cfg));
	cfg.sink = sink;
	cfg.resource = &test_resource;
	cfg.batch_size = 1;
	for (i = 1; i <= 120; i++) {
		failalloc_arm(i);
		e = oe_otlpjson_new(&cfg);
		if (e != NULL) {
			(void)oe_event(e, &ev);
			(void)oe_span(e, &root);
			sn = make_snapshot(OE_AGG_QUANTIZE, "q");
			(void)oe_snapshot(e, &sn);
			sn = make_snapshot(OE_AGG_COUNT, "c");
			(void)oe_snapshot(e, &sn);
			(void)oe_flush(e);
		}
		failalloc_arm(0);
		if (e != NULL)
			oe_exporter_free(e);
	}
	oe_sink_close(sink);
}


/* More failure paths: spool line allocation, rotation steps, odd spools. */
ATF_TC(failure_edges);
ATF_TC_HEAD(failure_edges, tc)
{

	atf_tc_set_md_var(tc, "require.user", "unprivileged");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(failure_edges, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	struct oe_exporter *e;
	struct oe_event ev;
	struct rlimit rl;
	FILE *fp;
	char buf[4096];
	int port, i, fd;

	ev = make_event();
	/* Spooling while allocations fail: batches are lost, not torn. */
	port = closed_port();
	for (i = 1; i <= 60; i++) {
		e = otlp_to(port, "http", "f.jsonl", 0, 0, NULL);
		ATF_REQUIRE(e != NULL);
		failalloc_arm(i);
		(void)oe_event(e, &ev);
		(void)oe_flush(e);
		failalloc_arm(0);
		oe_shutdown(e);
		oe_exporter_free(e);
	}
	/* A spool that is not a regular file. */
	ATF_REQUIRE(otlp_to(port, "http", "/dev/null", 0, 0, NULL) == NULL);
	/* Rotation: the oldest slot is a non-empty directory. */
	ATF_REQUIRE_EQ(0, mkdir("r.log.2", 0755));
	fp = fopen("r.log.2/x", "w");
	fclose(fp);
	memset(&sc, 0, sizeof(sc));
	sc.path = "r.log";
	sc.rotate_size = 2;
	sc.rotate_keep = 2;
	s = oe_sink_open(&sc);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "ab", 2));
	ATF_REQUIRE_EQ(-1, oe_sink_write(s, "cd", 2));
	ATF_REQUIRE_EQ(-1, oe_sink_close(s));
	/* Rotation: shifting path.1 up fails in a read-only directory. */
	ATF_REQUIRE_EQ(0, mkdir("rod", 0755));
	sc.path = "rod/q.log";
	sc.rotate_keep = 3;
	s = oe_sink_open(&sc);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "ab", 2));
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "cd", 2));	/* rotated once */
	ATF_REQUIRE_EQ(0, chmod("rod", 0555));
	ATF_REQUIRE_EQ(-1, oe_sink_write(s, "ef", 2));
	ATF_REQUIRE_EQ(-1, oe_sink_close(s));
	ATF_REQUIRE_EQ(0, chmod("rod", 0755));
	/* Rotation: the buffered data cannot be flushed (disk full). */
	signal(SIGXFSZ, SIG_IGN);
	fd = open("full.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	memset(buf, 'x', sizeof(buf));
	ATF_REQUIRE_EQ(2000, write(fd, buf, 2000));
	close(fd);
	rl.rlim_cur = 4096;
	rl.rlim_max = RLIM_INFINITY;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_FSIZE, &rl));
	sc.path = "full.log";
	sc.rotate_size = 4500;
	s = oe_sink_open(&sc);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, buf, 2400));	/* buffered */
	ATF_REQUIRE_EQ(-1, oe_sink_write(s, buf, 200));
	ATF_REQUIRE_EQ(-1, oe_sink_close(s));
	rl.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &rl);
}

ATF_TC_WITHOUT_HEAD(exporter_small_edges);
ATF_TC_BODY(exporter_small_edges, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_sink_config sc;
	struct oe_sink *sink;
	FILE *fp;
	char *out;
	size_t outlen;

	/* Collapsed: a kernel-only stack; a write error mid-dump. */
	fp = open_memstream(&out, &outlen);
	e = oe_collapsed_new(fp);
	ev = make_event();
	ev.nustack = 0;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_exporter_free(e);
	fclose(fp);
	free(out);
	fp = fwopen(NULL, enospc_write);
	setvbuf(fp, NULL, _IONBF, 0);
	e = oe_collapsed_new(fp);
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.execname = "other";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(-1, oe_shutdown(e));
	oe_exporter_free(e);
	fclose(fp);
	/* JSONL with an empty probe; OTLP JSON with an empty body. */
	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "p");
	ev = make_event();
	ev.probe = "";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	{
		struct oe_span root, child;

		make_spans(&root, &child);
		failalloc_arm(1);
		ATF_REQUIRE_EQ(-1, oe_span(e, &root));
		failalloc_arm(0);
	}
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "\"probe\"") == NULL);
	free(out);
	fp = open_memstream(&out, &outlen);
	memset(&sc, 0, sizeof(sc));
	sc.fp = fp;
	sink = oe_sink_open(&sc);
	e = otlpjson_on(sink, 0);
	ev.body = "";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	oe_exporter_free(e);
	oe_sink_close(sink);
	fclose(fp);
	ATF_REQUIRE_EQ(0, outlen);
	free(out);
}


/* Allocation failures while a full batch becomes a request. */
ATF_TC_WITHOUT_HEAD(otlp_batch_alloc);
ATF_TC_BODY(otlp_batch_alloc, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	int i, port;

	port = closed_port();
	ev = make_event();
	for (i = 1; i <= 40; i++) {
		e = otlp_to(port, "http", NULL, 0, 0, NULL);
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		failalloc_arm(i);
		(void)oe_event(e, &ev);		/* the batch fills */
		failalloc_arm(0);
		oe_exporter_free(e);
	}
}

/* Each exporter holds its spool; a second one is refused or goes without. */
ATF_TC_WITHOUT_HEAD(otlp_spool_lock);
ATF_TC_BODY(otlp_spool_lock, tc)
{
	struct oe_otlp_config cfg;
	struct oe_exporter *e1, *e2;
	int port;

	port = closed_port();
	e1 = otlp_to(port, "http", "s.jsonl", 0, 0, NULL);
	ATF_REQUIRE(e1 != NULL);
	ATF_REQUIRE(access("s.jsonl.lock", F_OK) == 0);
	/* An explicit spool another exporter holds fails creation. */
	ATF_CHECK(otlp_to(port, "http", "s.jsonl", 0, 0, NULL) == NULL);
	/* An optional (system) spool is reported and left unused. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = "http://127.0.0.1:9";
	cfg.profile = "test-prof";
	cfg.resource = &test_resource;
	cfg.spool_path = "s.jsonl";
	cfg.spool_optional = 1;
	e2 = oe_otlp_new(&cfg);
	ATF_REQUIRE(e2 != NULL);
	oe_exporter_free(e2);
	cfg.spool_path = "nodir/s.jsonl";
	e2 = oe_otlp_new(&cfg);
	ATF_REQUIRE(e2 != NULL);
	oe_exporter_free(e2);
	/* A spool that is not a regular file is refused. */
	ATF_REQUIRE(symlink("/dev/null", "null.jsonl") == 0);
	ATF_CHECK(otlp_to(port, "http", "null.jsonl", 0, 0, NULL) == NULL);
	/* Released with the exporter. */
	oe_exporter_free(e1);
	e2 = otlp_to(port, "http", "s.jsonl", 0, 0, NULL);
	ATF_REQUIRE(e2 != NULL);
	oe_exporter_free(e2);
}

/* severityText for every range and offset, invalid values as INFO. */
ATF_TC_WITHOUT_HEAD(severity_text);
ATF_TC_BODY(severity_text, tc)
{
	char buf[16];

	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_TRACE, buf, sizeof(buf)),
	    "TRACE");
	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_DEBUG, buf, sizeof(buf)),
	    "DEBUG");
	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_INFO, buf, sizeof(buf)),
	    "INFO");
	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_WARN, buf, sizeof(buf)),
	    "WARN");
	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_ERROR, buf, sizeof(buf)),
	    "ERROR");
	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_FATAL, buf, sizeof(buf)),
	    "FATAL");
	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_WARN + 1, buf, sizeof(buf)),
	    "WARN2");
	ATF_CHECK_STREQ(oe_severity_text(OE_SEV_FATAL + 3, buf, sizeof(buf)),
	    "FATAL4");
	ATF_CHECK_STREQ(oe_severity_text(0, buf, sizeof(buf)), "INFO");
	ATF_CHECK_STREQ(oe_severity_text(25, buf, sizeof(buf)), "INFO");
	ATF_CHECK_STREQ(oe_severity_text(-3, buf, sizeof(buf)), "INFO");
}

/* Log records carry the event's severity and extra attributes. */
ATF_TC_WITHOUT_HEAD(log_severity_attrs);
ATF_TC_BODY(log_severity_attrs, tc)
{
	static const struct oe_kv kv[] = {
		{ "user.id", OE_VAL_STRING, "1001", 0, 0 },
		{ "test.return", OE_VAL_INT, NULL, -13, 0 },
	};
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct otlp_counts c;
	char *text;

	memset(&sc, 0, sizeof(sc));
	sc.path = "out.jsonl";
	sink = oe_sink_open(&sc);
	ATF_REQUIRE(sink != NULL);
	e = otlpjson_on(sink, 0);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	ev = make_event();
	fixed_event_times(&ev);
	ev.severity = OE_SEV_WARN;
	ev.attrs = kv;
	ev.nattrs = nitems(kv);
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.severity = OE_SEV_ERROR + 2;
	ev.nattrs = 0;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.severity = (enum oe_severity)99;	/* invalid: INFO */
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(0, oe_sink_close(sink));
	text = slurp("out.jsonl", NULL);
	c = check_otlp_lines(tc, text, NULL);
	ATF_CHECK_EQ(3, c.logs);
	ATF_CHECK(strstr(text, "\"severityNumber\":13,\"severityText\":"
	    "\"WARN\"") != NULL);
	ATF_CHECK(strstr(text, "\"severityNumber\":19,\"severityText\":"
	    "\"ERROR3\"") != NULL);
	ATF_CHECK(strstr(text, "\"severityNumber\":9,\"severityText\":"
	    "\"INFO\"") != NULL);
	ATF_CHECK(strstr(text, "{\"key\":\"user.id\",\"value\":"
	    "{\"stringValue\":\"1001\"}}") != NULL);
	ATF_CHECK(strstr(text, "{\"key\":\"test.return\",\"value\":"
	    "{\"intValue\":\"-13\"}}") != NULL);
	free(text);
}

/* ---------------------------------------------------------------- */
/* Transport failures below the exporter (oe_http_post)		 	*/

struct rst_peer {
	int	 lfd;
	int	 port;
	pthread_t thread;
};

/* Accept one connection and reset it at once (SO_LINGER 0). */
static void *
rst_peer_main(void *arg)
{
	struct rst_peer *p = arg;
	struct linger lg = { 1, 0 };
	int fd;

	fd = accept(p->lfd, NULL, NULL);
	if (fd >= 0) {
		(void)setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		close(fd);
	}
	return (NULL);
}

static void
rst_peer_start(struct rst_peer *p)
{
	struct sockaddr_in sin;
	socklen_t len;

	p->lfd = socket(AF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE(p->lfd >= 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(p->lfd, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE(listen(p->lfd, 1) == 0);
	len = sizeof(sin);
	ATF_REQUIRE(getsockname(p->lfd, (struct sockaddr *)&sin, &len) == 0);
	p->port = ntohs(sin.sin_port);
	ATF_REQUIRE(pthread_create(&p->thread, NULL, rst_peer_main, p) == 0);
}

static void
rst_peer_stop(struct rst_peer *p)
{

	pthread_join(p->thread, NULL);
	close(p->lfd);
}

ATF_TC_WITHOUT_HEAD(http_transport_errors);
ATF_TC_BODY(http_transport_errors, tc)
{
	struct oe_http_response resp;
	struct rst_peer peer;
	struct oe_attr hdr;
	struct oe_url u;
	struct rlimit rl, saved;
	char url[64], *big;
	size_t biglen = 8 * 1024 * 1024;
	int next;

	/* A peer that resets during the TLS handshake: no TLS error. */
	rst_peer_start(&peer);
	snprintf(url, sizeof(url), "https://127.0.0.1:%d", peer.port);
	ATF_REQUIRE_EQ(0, oe_url_parse(url, &u));
	ATF_CHECK_EQ(-1, oe_http_post(&u, "v1/logs", NULL, 0, "t", "{}", 2, 0,
	    2000, &resp));
	ATF_CHECK_EQ(-1, resp.status);
	ATF_CHECK_MSG(strstr(resp.errmsg, "TLS handshake") != NULL, "%s",
	    resp.errmsg);
	rst_peer_stop(&peer);

	/* A peer that resets while the request is still being sent. */
	rst_peer_start(&peer);
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", peer.port);
	ATF_REQUIRE_EQ(0, oe_url_parse(url, &u));
	big = malloc(biglen);
	ATF_REQUIRE(big != NULL);
	memset(big, 'x', biglen);
	ATF_CHECK_EQ(-1, oe_http_post(&u, "v1/logs", NULL, 0, "t", big, biglen,
	    0, 2000, &resp));
	ATF_CHECK_EQ(-1, resp.status);
	ATF_CHECK_MSG(strstr(resp.errmsg, "send to 127.0.0.1") != NULL ||
	    strstr(resp.errmsg, "connect") != NULL, "%s", resp.errmsg);
	rst_peer_stop(&peer);
	/* ... or while its headers are (an oversized header value). */
	big[biglen - 1] = '\0';
	hdr.name = "X-Big";
	hdr.value = big;
	rst_peer_start(&peer);
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", peer.port);
	ATF_REQUIRE_EQ(0, oe_url_parse(url, &u));
	ATF_CHECK_EQ(-1, oe_http_post(&u, "v1/logs", &hdr, 1, "t", "{}", 2,
	    0, 2000, &resp));
	ATF_CHECK_EQ(-1, resp.status);
	free(big);
	rst_peer_stop(&peer);

	/* No descriptor left for a socket. */
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", closed_port());
	ATF_REQUIRE_EQ(0, oe_url_parse(url, &u));
	next = dup(0);
	ATF_REQUIRE(next >= 0);
	close(next);
	ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &saved) == 0);
	rl = saved;
	rl.rlim_cur = (rlim_t)next;
	ATF_REQUIRE(setrlimit(RLIMIT_NOFILE, &rl) == 0);
	ATF_CHECK_EQ(-1, oe_http_post(&u, "v1/logs", NULL, 0, "t", "{}", 2, 0,
	    2000, &resp));
	ATF_REQUIRE(setrlimit(RLIMIT_NOFILE, &saved) == 0);
	ATF_CHECK_EQ(-1, resp.status);

	/* A name that can never resolve (RFC 6761 .invalid). */
	setenv("RES_OPTIONS", "attempts:1 timeout:1", 1);
	ATF_REQUIRE_EQ(0, oe_url_parse("http://otel-test.invalid:4318", &u));
	ATF_CHECK_EQ(-1, oe_http_post(&u, "v1/logs", NULL, 0, "t", "{}", 2, 0,
	    2000, &resp));
	ATF_CHECK_EQ(-1, resp.status);
	unsetenv("RES_OPTIONS");
}

/* A host name buffer too small for the name gets the fallback, cut. */
ATF_TC_WITHOUT_HEAD(host_name_small);
ATF_TC_BODY(host_name_small, tc)
{
	char buf[3], full[256];

	oe_host_name(full, sizeof(full));
	if (strlen(full) < sizeof(buf))
		atf_tc_skip("host name \"%s\" fits", full);
	oe_host_name(buf, sizeof(buf));
	ATF_CHECK_STREQ(buf, "lo");
}

/* Ids wider than a SHA-256 digest cannot be derived: random instead. */
ATF_TC_WITHOUT_HEAD(id_derive_wide);
ATF_TC_BODY(id_derive_wide, tc)
{
	static const uint8_t salt[16] = { 1, 2, 3 };
	const int64_t key[2] = { 7, 8 };
	uint8_t a[40], b[40];

	oe_id_derive(salt, "ns", key, 2, a, sizeof(a));
	oe_id_derive(salt, "ns", key, 2, b, sizeof(b));
	ATF_CHECK(!oe_id_is_zero(a, sizeof(a)));
	ATF_CHECK(memcmp(a, b, sizeof(a)) != 0);
	/* A span-sized id is stable. */
	oe_id_derive(salt, "ns", key, 2, a, OE_SPAN_ID_LEN);
	oe_id_derive(salt, "ns", key, 2, b, OE_SPAN_ID_LEN);
	ATF_CHECK(memcmp(a, b, OE_SPAN_ID_LEN) == 0);
}

/* Aggregation snapshots, severity and event attributes in JSONL. */
ATF_TC_WITHOUT_HEAD(jsonl_metrics);
ATF_TC_BODY(jsonl_metrics, tc)
{
	static const struct oe_kv kv[] = {
		{ "user.id", OE_VAL_STRING, "7", 0, 0 },
	};
	static const struct oe_attr res[] = { { "host.name", "vm1" } };
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_snapshot sn;
	struct oe_event ev;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "test-prof");
	ATF_REQUIRE_EQ(0, oe_start(e));
	sn = make_snapshot(OE_AGG_SUM, "bytes");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	sn = make_snapshot(OE_AGG_QUANTIZE, "");	/* anonymous */
	sn.start.tv_sec = 0;
	sn.profile = NULL;
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	sn.npoints = 0;					/* skipped */
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ev = make_event();
	ev.severity = OE_SEV_ERROR;
	ev.attrs = kv;
	ev.nattrs = 1;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_shutdown(e);
	oe_exporter_free(e);
	fclose(fp);
	ATF_CHECK(strstr(out, "{\"type\":\"metric\",\"time\":"
	    "\"2023-11-14T22:13:30.000Z\",\"start\":\"2023-11-14T22:13:20.000Z\","
	    "\"profile\":\"test-prof\",\"name\":\"bytes\",\"kind\":\"sum\","
	    "\"points\":[{\"attributes\":{\"process.executable.name\":\"nginx\","
	    "\"syscall\":\"read\"},\"value\":42},{\"attributes\":"
	    "{\"process.executable.name\":\"nginx\"},\"buckets\":[{\"le\":7,"
	    "\"count\":4},{\"le\":1,\"count\":2},{\"le\":9223372036854775807,"
	    "\"count\":1}]}]}\n") != NULL);
	ATF_CHECK(strstr(out, "\"time\":\"2023-11-14T22:13:30.000Z\","
	    "\"profile\":\"test-prof\",\"name\":\"quantize\",\"kind\":"
	    "\"quantize\"") != NULL);
	ATF_CHECK(strstr(out, "\"severity\":\"ERROR\"") != NULL);
	ATF_CHECK(strstr(out, "\"user.id\":\"7\"") != NULL);
	free(out);

	/* A NULL name is anonymous too; a failing allocation fails. */
	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "test-prof");
	sn = make_snapshot(OE_AGG_MAX, NULL);
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	failalloc_arm(1);
	ATF_CHECK_EQ(-1, oe_snapshot(e, &sn));
	failalloc_arm(0);
	oe_shutdown(e);
	oe_exporter_free(e);
	fclose(fp);
	ATF_CHECK(strstr(out, "\"name\":\"max\",\"kind\":\"max\"") != NULL);
	free(out);

	/* A resource-tagged stream names it on metric lines too. */
	memset(&sc, 0, sizeof(sc));
	sc.path = "res.jsonl";
	sink = oe_sink_open(&sc);
	ATF_REQUIRE(sink != NULL);
	e = oe_jsonl_resource_new(sink, "p", res, 1);
	ATF_REQUIRE(e != NULL);
	sn = make_snapshot(OE_AGG_COUNT, "c");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	oe_shutdown(e);
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(0, oe_sink_close(sink));
	out = slurp("res.jsonl", NULL);
	ATF_CHECK(strstr(out, "\"kind\":\"count\"") != NULL);
	ATF_CHECK(strstr(out, "\"resource\":{\"host.name\":\"vm1\"}") != NULL);
	free(out);
}

/* ---------------------------------------------------------------- */
/* External rotation (newsyslog) and the otel.conf file target		*/

/* Lines of a file, or 0 when it does not exist. */
static size_t
lines_or_zero(const char *path)
{
	size_t n = count_lines(path);

	return (n == (size_t)-1 ? 0 : n);
}

/* What newsyslog(8) does: rename away, then move a new file in place. */
static void
newsyslog_rotate(const char *path, const char *to)
{
	char tmp[PATH_MAX];
	int fd;

	ATF_REQUIRE(rename(path, to) == 0);
	snprintf(tmp, sizeof(tmp), "%s.zXXXXXX", path);
	fd = mkstemp(tmp);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(fchmod(fd, 0640) == 0);
	close(fd);
	ATF_REQUIRE(rename(tmp, path) == 0);
}

ATF_TC_WITHOUT_HEAD(sink_follow_rename);
ATF_TC_BODY(sink_follow_rename, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	struct stat st;
	char rec[32];
	int i;

	memset(&sc, 0, sizeof(sc));
	sc.path = "t.jsonl";
	sc.durable = 1;
	sc.mode = 0640;
	sc.follow = 1;
	umask(022);
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE(stat("t.jsonl", &st) == 0);
	ATF_CHECK_EQ(st.st_mode & ALLPERMS, 0640);
	for (i = 0; i < 3; i++) {
		snprintf(rec, sizeof(rec), "{\"r\":%d}\n", i);
		ATF_REQUIRE_EQ(0, oe_sink_write(s, rec, strlen(rec)));
	}
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	/*
	 * Rotated without a signal: records written before the next flush
	 * still go to the open (rotated) file, whole; that flush notices
	 * the new file and later records go there.
	 */
	newsyslog_rotate("t.jsonl", "t.jsonl.0");
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "{\"r\":3}\n", 8));
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "{\"r\":4}\n", 8));
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_CHECK_EQ(4, lines_or_zero("t.jsonl.0"));
	ATF_CHECK_EQ(1, lines_or_zero("t.jsonl"));
	/* newsyslog's mode is kept; the file was not recreated by us. */
	ATF_REQUIRE(stat("t.jsonl", &st) == 0);
	ATF_CHECK_EQ(st.st_mode & ALLPERMS, 0640);

	/* With the signal: reopened before the very next write. */
	newsyslog_rotate("t.jsonl", "t.jsonl.1");
	oe_sink_reopen_request();
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "{\"r\":5}\n", 8));
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_CHECK_EQ(1, lines_or_zero("t.jsonl.1"));
	ATF_CHECK_EQ(1, lines_or_zero("t.jsonl"));
	/* A request is acted on once. */
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "{\"r\":6}\n", 8));
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_CHECK_EQ(2, lines_or_zero("t.jsonl"));

	/*
	 * A missing path is the window in which newsyslog has renamed
	 * the old file but not yet moved the new one in: not created at
	 * once, so no record lands in a file about to be replaced.  After
	 * a few flushes it is (someone removed it for good).
	 */
	ATF_REQUIRE(rename("t.jsonl", "t.jsonl.2") == 0);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "{\"r\":7}\n", 8));
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_CHECK(stat("t.jsonl", &st) != 0 && errno == ENOENT);
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_CHECK(stat("t.jsonl", &st) != 0 && errno == ENOENT);
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_CHECK(stat("t.jsonl", &st) == 0);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "{\"r\":8}\n", 8));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_CHECK_EQ(3, lines_or_zero("t.jsonl.2"));
	ATF_CHECK_EQ(1, lines_or_zero("t.jsonl"));
	/* Every record exactly once across the files. */
	ATF_CHECK_EQ(9, lines_or_zero("t.jsonl") + lines_or_zero("t.jsonl.0") +
	    lines_or_zero("t.jsonl.1") + lines_or_zero("t.jsonl.2"));
}

ATF_TC_WITHOUT_HEAD(sink_follow_edges);
ATF_TC_BODY(sink_follow_edges, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;

	/* A sink that does not follow ignores requests and renames. */
	memset(&sc, 0, sizeof(sc));
	sc.path = "plain.log";
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "a\n", 2));
	ATF_REQUIRE(rename("plain.log", "plain.log.0") == 0);
	oe_sink_reopen_request();
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "b\n", 2));
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_CHECK_EQ(2, lines_or_zero("plain.log.0"));
	ATF_CHECK_EQ(0, lines_or_zero("plain.log"));

	/* Explicit reopen: a no-op for streams, a new file otherwise. */
	memset(&sc, 0, sizeof(sc));
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_CHECK_EQ(0, oe_sink_reopen(s));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	sc.path = "r.log";
	sc.durable = 1;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "a\n", 2));
	ATF_REQUIRE(rename("r.log", "r.log.0") == 0);
	ATF_REQUIRE_EQ(0, oe_sink_reopen(s));
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "b\n", 2));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_CHECK_EQ(1, lines_or_zero("r.log.0"));
	ATF_CHECK_EQ(1, lines_or_zero("r.log"));

	/*
	 * A reopen that cannot create the file fails stickily, with the
	 * records before it kept.
	 */
	ATF_REQUIRE(mkdir("d", 0755) == 0);
	sc.path = "d/x.log";
	sc.follow = 1;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "a\n", 2));
	ATF_REQUIRE(rename("d/x.log", "x.log.0") == 0);
	ATF_REQUIRE(rmdir("d") == 0);
	oe_sink_reopen_request();
	ATF_CHECK_EQ(-1, oe_sink_write(s, "b\n", 2));
	ATF_CHECK_EQ(-1, oe_sink_flush(s));
	ATF_CHECK_EQ(-1, oe_sink_reopen(s));
	ATF_CHECK_EQ(-1, oe_sink_close(s));
	ATF_CHECK_EQ(1, lines_or_zero("x.log.0"));
	/* The same failure found by a flush (path gone, no signal). */
	ATF_REQUIRE(mkdir("d", 0755) == 0);
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE(rename("d/x.log", "x.log.1") == 0);
	ATF_REQUIRE(rmdir("d") == 0);
	ATF_CHECK_EQ(0, oe_sink_flush(s));
	ATF_CHECK_EQ(0, oe_sink_flush(s));
	ATF_CHECK_EQ(-1, oe_sink_flush(s));
	ATF_CHECK_EQ(-1, oe_sink_close(s));
	/* A path that cannot be examined is left alone. */
	ATF_REQUIRE(mkdir("e", 0755) == 0);
	sc.path = "e/y.log";
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	if (getuid() != 0) {
		ATF_REQUIRE(chmod("e", 0) == 0);
		ATF_CHECK_EQ(0, oe_sink_flush(s));
		ATF_CHECK_EQ(0, oe_sink_flush(s));
		ATF_CHECK_EQ(0, oe_sink_flush(s));
		ATF_CHECK_EQ(0, oe_sink_flush(s));
		ATF_REQUIRE(chmod("e", 0755) == 0);
	}
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "a\n", 2));
	/* A request seen first by a flush reopens there. */
	ATF_REQUIRE(rename("e/y.log", "y.log.0") == 0);
	oe_sink_reopen_request();
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "b\n", 2));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_CHECK_EQ(1, lines_or_zero("y.log.0"));
	ATF_CHECK_EQ(1, lines_or_zero("e/y.log"));

	/* Not durable: reopened without directory syncs. */
	sc.durable = 0;
	sc.path = "nd.log";
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	newsyslog_rotate("nd.log", "nd.log.0");
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "a\n", 2));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_CHECK_EQ(1, lines_or_zero("nd.log"));

	/*
	 * The path now names a file on another file system (a device):
	 * a different file, and one the sink refuses to write.
	 */
	sc.path = "dev.log";
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE(unlink("dev.log") == 0);
	ATF_REQUIRE(symlink("/dev/null", "dev.log") == 0);
	ATF_CHECK_EQ(-1, oe_sink_flush(s));
	ATF_CHECK_EQ(-1, oe_sink_close(s));

	/* Buffered records that cannot be written fail the reopen. */
	sc.path = "big.log";
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	{
		struct rlimit rl, saved;
		char big[64];

		signal(SIGXFSZ, SIG_IGN);
		ATF_REQUIRE(getrlimit(RLIMIT_FSIZE, &saved) == 0);
		rl = saved;
		rl.rlim_cur = 16;
		ATF_REQUIRE(setrlimit(RLIMIT_FSIZE, &rl) == 0);
		memset(big, 'x', sizeof(big));
		ATF_REQUIRE_EQ(0, oe_sink_write(s, big, sizeof(big)));
		ATF_CHECK_EQ(-1, oe_sink_reopen(s));
		ATF_REQUIRE(setrlimit(RLIMIT_FSIZE, &saved) == 0);
	}
	ATF_CHECK_EQ(-1, oe_sink_close(s));
}

ATF_TC_WITHOUT_HEAD(file_target_exporter);
ATF_TC_BODY(file_target_exporter, tc)
{
	struct oe_otlp_config cfg;
	struct oe_env env;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	struct otlp_counts c;
	struct stat st;
	char *text;

	memset(&env, 0, sizeof(env));
	env.endpoint = OE_DEFAULT_ENDPOINT;
	env.file_path = "tool.jsonl";
	memset(&cfg, 0, sizeof(cfg));
	cfg.profile = "p";
	cfg.resource = &test_resource;
	cfg.scope_name = "tool";
	cfg.batch_size = 2;
	umask(022);
	e = oe_exporter_open(&env, &cfg);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE(stat("tool.jsonl", &st) == 0);
	ATF_CHECK_EQ(st.st_mode & ALLPERMS, OE_FILE_TARGET_MODE);
	ATF_REQUIRE_EQ(0, oe_start(e));
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	sn = make_snapshot(OE_AGG_COUNT, "n");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	/* A flush writes the pending lines (the services' durability). */
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_CHECK_EQ(2, lines_or_zero("tool.jsonl"));
	/* Rotation is followed through the exporter's flush. */
	newsyslog_rotate("tool.jsonl", "tool.jsonl.0");
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	/* Shutdown closed the owned sink; free must not close it again. */
	oe_exporter_free(e);
	ATF_CHECK_EQ(1, lines_or_zero("tool.jsonl"));
	text = slurp("tool.jsonl.0", NULL);
	ATF_REQUIRE(text != NULL);
	c = check_otlp_lines(tc, text, NULL);
	ATF_CHECK_EQ(c.logs, 1);
	ATF_CHECK_EQ(c.metrics, 1);
	ATF_CHECK(strstr(text, "\"scope\":{\"name\":\"tool\"") != NULL);
	free(text);
	text = slurp("tool.jsonl", NULL);
	c = check_otlp_lines(tc, text, NULL);
	ATF_CHECK_EQ(c.logs, 1);
	free(text);

	/* Freed without shutdown: the sink is still closed. */
	e = oe_exporter_open(&env, &cfg);
	ATF_REQUIRE(e != NULL);
	oe_exporter_free(e);

	/* Allocation failures while creating it leave nothing behind. */
	{
		int i;

		for (i = 1; i <= 20; i++) {
			failalloc_arm(i);
			e = oe_exporter_open(&env, &cfg);
			failalloc_arm(0);
			if (e != NULL)
				oe_exporter_free(e);
		}
	}

	/* A write error surfaces at shutdown, which still closes. */
	e = oe_exporter_open(&env, &cfg);
	ATF_REQUIRE(e != NULL);
	{
		struct rlimit rl, saved;

		signal(SIGXFSZ, SIG_IGN);
		ATF_REQUIRE(getrlimit(RLIMIT_FSIZE, &saved) == 0);
		rl = saved;
		rl.rlim_cur = 0;
		ATF_REQUIRE(setrlimit(RLIMIT_FSIZE, &rl) == 0);
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		ATF_CHECK_EQ(-1, oe_shutdown(e));
		oe_exporter_free(e);
		ATF_REQUIRE(setrlimit(RLIMIT_FSIZE, &saved) == 0);
	}

	/* An unopenable file target fails creation. */
	env.file_path = "nonexistent-dir/tool.jsonl";
	ATF_CHECK(oe_exporter_open(&env, &cfg) == NULL);
	/* Without a file target there is no file sink. */
	env.file_path = NULL;
	ATF_CHECK(oe_env_sink_open(&env) == NULL);
	/* ... and the exporter is OTLP/HTTP to the resolved endpoint. */
	env.endpoint = "http://127.0.0.1:9";
	e = oe_exporter_open(&env, &cfg);
	ATF_REQUIRE(e != NULL);
	oe_exporter_free(e);
	env.endpoint = "notaurl";
	ATF_CHECK(oe_exporter_open(&env, &cfg) == NULL);
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
	ATF_TP_ADD_TC(tp, otlp_spool_lock);
	ATF_TP_ADD_TC(tp, severity_text);
	ATF_TP_ADD_TC(tp, log_severity_attrs);
	ATF_TP_ADD_TC(tp, http_transport_errors);
	ATF_TP_ADD_TC(tp, id_derive_wide);
	ATF_TP_ADD_TC(tp, host_name_small);
	ATF_TP_ADD_TC(tp, jsonl_metrics);
	ATF_TP_ADD_TC(tp, otlp_tls);
	ATF_TP_ADD_TC(tp, otlp_alloc_failure);
	ATF_TP_ADD_TC(tp, span_ids);
	ATF_TP_ADD_TC(tp, span_otlpjson_golden);
	ATF_TP_ADD_TC(tp, span_doubles);
	ATF_TP_ADD_TC(tp, span_jsonl_text);
	ATF_TP_ADD_TC(tp, span_http);
	ATF_TP_ADD_TC(tp, validator_rejects);
	ATF_TP_ADD_TC(tp, validator_accepts);
	ATF_TP_ADD_TC(tp, semconv_golden);
	ATF_TP_ADD_TC(tp, semconv_jsonl);
	ATF_TP_ADD_TC(tp, host_detection);
	ATF_TP_ADD_TC(tp, utf8_all_formats);
	ATF_TP_ADD_TC(tp, collapsed_edges);
	ATF_TP_ADD_TC(tp, text_every_kind);
	ATF_TP_ADD_TC(tp, jsonl_edges);
	ATF_TP_ADD_TC(tp, otlp_encoding_edges);
	ATF_TP_ADD_TC(tp, otlp_http_edges);
	ATF_TP_ADD_TC(tp, otlp_job_queue);
	ATF_TP_ADD_TC(tp, otlp_spool_edges);
	ATF_TP_ADD_TC(tp, sink_edges);
	ATF_TP_ADD_TC(tp, util_edges);
	ATF_TP_ADD_TC(tp, alloc_sweeps);
	ATF_TP_ADD_TC(tp, failure_edges);
	ATF_TP_ADD_TC(tp, exporter_small_edges);
	ATF_TP_ADD_TC(tp, otlp_batch_alloc);
	ATF_TP_ADD_TC(tp, sink_follow_rename);
	ATF_TP_ADD_TC(tp, sink_follow_edges);
	ATF_TP_ADD_TC(tp, file_target_exporter);
	return (atf_no_error());
}
