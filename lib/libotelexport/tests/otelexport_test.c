/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for libotelexport: string buffer, JSON escaping, frame
 * formatting, OTel environment parsing, URL parsing, and the three
 * stdout exporters (text, JSONL, collapsed) via open_memstream.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_http.h"

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
	setenv("OTEL_RESOURCE_ATTRIBUTES", "env=prod,team=kernel", 1);
	setenv("OTEL_EXPORTER_OTLP_HEADERS",
	    "Authorization=Basic dXNlcjpwYXNz", 1);
	oe_env_load(&env);
	ATF_REQUIRE_STREQ("mysvc", env.service_name);
	ATF_REQUIRE_STREQ("http://collector:4318", env.endpoint);
	ATF_REQUIRE_EQ(2500, env.timeout_ms);
	ATF_REQUIRE_EQ(2, env.nresource_attrs);
	ATF_REQUIRE_STREQ("env", env.resource_attrs[0].name);
	ATF_REQUIRE_STREQ("prod", env.resource_attrs[0].value);
	ATF_REQUIRE_STREQ("team", env.resource_attrs[1].name);
	ATF_REQUIRE_EQ(1, env.nheaders);
	ATF_REQUIRE_STREQ("Authorization", env.headers[0].name);
	ATF_REQUIRE_STREQ("Basic dXNlcjpwYXNz", env.headers[0].value);
	oe_env_free(&env);

	/* Malformed pairs (no '=') are skipped. */
	setenv("OTEL_RESOURCE_ATTRIBUTES", "noequals,a=b", 1);
	oe_env_load(&env);
	ATF_REQUIRE_EQ(1, env.nresource_attrs);
	ATF_REQUIRE_STREQ("a", env.resource_attrs[0].name);
	oe_env_free(&env);
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
	return (atf_no_error());
}
