/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Per-signal exporter settings: OTEL_EXPORTER_OTLP_{LOGS,METRICS,TRACES,
 * PROFILES}_{ENDPOINT,PROTOCOL,HEADERS,TIMEOUT,COMPRESSION}, the otel.conf(5)
 * signal blocks, their precedence (command line > signal variable >
 * general variable > otel.conf signal block > general otel.conf keys >
 * default), where credentials go, and one exporter sending each signal
 * over its own transport to its own loopback receiver.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_otlpenc.h"
#include "oe_sysconf.h"
#include "grpc_testsrv.h"
#include "otel_testutil.h"

static const char *const sigvars[] = { "LOGS", "METRICS", "TRACES",
    "PROFILES" };
static const char *const settings[] = { "ENDPOINT", "PROTOCOL", "HEADERS",
    "TIMEOUT", "COMPRESSION" };

/* No OTEL_* variable leaks in from the environment. */
static void
clean_env(void)
{
	char var[64];
	size_t i, j;

	for (j = 0; j < nitems(settings); j++) {
		snprintf(var, sizeof(var), "OTEL_EXPORTER_OTLP_%s",
		    settings[j]);
		unsetenv(var);
		for (i = 0; i < nitems(sigvars); i++) {
			snprintf(var, sizeof(var), "OTEL_EXPORTER_OTLP_%s_%s",
			    sigvars[i], settings[j]);
			unsetenv(var);
		}
	}
	unsetenv("OTEL_SERVICE_NAME");
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
	setenv("OTELCONF_DEFAULTS", "", 1);
	setenv("OTELCONF_FILE", "", 1);
}

static void
write_file(const char *path, const char *text, mode_t mode)
{
	int fd;

	ATF_REQUIRE((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode)) >=
	    0);
	ATF_REQUIRE_EQ((ssize_t)strlen(text), write(fd, text, strlen(text)));
	ATF_REQUIRE_EQ(0, fchmod(fd, mode));
	close(fd);
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
	fprintf(stderr, "%s", s);
	return (s);
}

/* A header's value in an attribute list, or NULL. */
static const char *
header(const struct oe_attr *h, size_t n, const char *name)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (strcmp(h[i].name, name) == 0)
			return (h[i].value);
	return (NULL);
}

/* ---------------------------------------------------------------- */
/* The variables							*/

ATF_TC_WITHOUT_HEAD(env_signal_vars);
ATF_TC_BODY(env_signal_vars, tc)
{
	struct oe_env env;
	char *err;
	int i;

	clean_env();
	setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://h:1/t", 1);
	setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc", 1);
	setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "a=1,b=%20two", 1);
	setenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "250", 1);
	setenv("OTEL_EXPORTER_OTLP_PROFILES_COMPRESSION", "none", 1);
	/* Malformed values are reported and left unset. */
	setenv("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "thrift", 1);
	setenv("OTEL_EXPORTER_OTLP_METRICS_COMPRESSION", "lz4", 1);
	setenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "soon", 1);
	setenv("OTEL_EXPORTER_OTLP_PROFILES_HEADERS", "noequals", 1);
	/* Present but empty: replaces the general headers with none. */
	setenv("OTEL_EXPORTER_OTLP_METRICS_HEADERS", " , ", 1);
	setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "", 1);
	/* Set but empty: not set. */
	setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "", 1);
	capture_start();
	oe_env_load(&env);
	err = capture_end();
	ATF_CHECK(strstr(err, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=thrift") !=
	    NULL);
	ATF_CHECK(strstr(err, "OTEL_EXPORTER_OTLP_METRICS_COMPRESSION=lz4") !=
	    NULL);
	ATF_CHECK(strstr(err, "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT=soon") !=
	    NULL);
	ATF_CHECK(strstr(err, "OTEL_EXPORTER_OTLP_PROFILES_HEADERS") != NULL);
	free(err);
	ATF_CHECK_STREQ("http://h:1/t",
	    env.signals[OE_SIGNAL_TRACES].endpoint);
	ATF_CHECK_EQ(1, env.signals[OE_SIGNAL_TRACES].endpoint_exact);
	ATF_CHECK(env.signals[OE_SIGNAL_LOGS].endpoint == NULL);
	ATF_CHECK_EQ(0, env.signals[OE_SIGNAL_LOGS].endpoint_exact);
	ATF_CHECK_STREQ("grpc", env.signals[OE_SIGNAL_TRACES].protocol);
	ATF_CHECK(env.signals[OE_SIGNAL_LOGS].protocol == NULL);
	ATF_CHECK_EQ(250, env.signals[OE_SIGNAL_METRICS].timeout_ms);
	ATF_CHECK_EQ(-1, env.signals[OE_SIGNAL_TRACES].timeout_ms);
	ATF_CHECK_STREQ("none", env.signals[OE_SIGNAL_PROFILES].compression);
	ATF_CHECK(env.signals[OE_SIGNAL_METRICS].compression == NULL);
	ATF_CHECK_EQ(2, env.signals[OE_SIGNAL_LOGS].nheaders);
	ATF_CHECK_STREQ(" two", header(env.signals[OE_SIGNAL_LOGS].headers,
	    2, "b"));
	ATF_CHECK_EQ(1, env.signal_headers_set[OE_SIGNAL_LOGS]);
	ATF_CHECK_EQ(1, env.signal_headers_set[OE_SIGNAL_METRICS]);
	ATF_CHECK_EQ(0, env.signals[OE_SIGNAL_METRICS].nheaders);
	ATF_CHECK_EQ(0, env.signal_headers_set[OE_SIGNAL_PROFILES]);
	ATF_CHECK_EQ(0, env.signal_headers_set[OE_SIGNAL_TRACES]);
	ATF_CHECK_EQ(0, env.signals_resolved);
	unsetenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS");
	for (i = 0; i < OE_NSIGNALS; i++)
		ATF_CHECK(strcmp(oe_signal_name((enum oe_signal)i),
		    "unknown") != 0);
	ATF_CHECK_STREQ("profiles", oe_signal_name(OE_SIGNAL_PROFILES));
	ATF_CHECK_STREQ("unknown", oe_signal_name((enum oe_signal)9));
	oe_env_free(&env);
}

/* Command line > signal variable > general variable > default. */
ATF_TC_WITHOUT_HEAD(config_precedence);
ATF_TC_BODY(config_precedence, tc)
{
	struct oe_config_request req;
	struct oe_env env;
	struct oe_otlp_config cfg;
	char err[256];

	clean_env();
	memset(&req, 0, sizeof(req));
	req.scope = "tool";
	/* Defaults follow each signal's protocol. */
	setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc", 1);
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	ATF_CHECK_EQ(1, env.endpoint_default);
	ATF_CHECK_EQ(1, env.signals_resolved);
	ATF_CHECK_STREQ(OE_DEFAULT_GRPC_ENDPOINT,
	    env.signals[OE_SIGNAL_TRACES].endpoint);
	ATF_CHECK_STREQ(OE_DEFAULT_ENDPOINT,
	    env.signals[OE_SIGNAL_LOGS].endpoint);
	ATF_CHECK_STREQ("http/protobuf", env.signals[OE_SIGNAL_LOGS].protocol);
	ATF_CHECK_EQ(-1, env.signals[OE_SIGNAL_LOGS].timeout_ms);
	oe_env_free(&env);

	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://gen:4318", 1);
	setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json", 1);
	setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "3000", 1);
	setenv("OTEL_EXPORTER_OTLP_HEADERS", "g=1", 1);
	setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip", 1);
	setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://m:1/met", 1);
	setenv("OTEL_EXPORTER_OTLP_METRICS_HEADERS", "m=2", 1);
	setenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "500", 1);
	setenv("OTEL_EXPORTER_OTLP_METRICS_COMPRESSION", "none", 1);
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	ATF_CHECK_EQ(0, env.endpoint_default);
	ATF_CHECK_STREQ("http://gen:4318",
	    env.signals[OE_SIGNAL_LOGS].endpoint);
	ATF_CHECK_EQ(0, env.signals[OE_SIGNAL_LOGS].endpoint_exact);
	ATF_CHECK_STREQ("http/json", env.signals[OE_SIGNAL_LOGS].protocol);
	ATF_CHECK_STREQ("grpc", env.signals[OE_SIGNAL_TRACES].protocol);
	ATF_CHECK_STREQ("http://gen:4318",
	    env.signals[OE_SIGNAL_TRACES].endpoint);
	ATF_CHECK_EQ(3000, env.signals[OE_SIGNAL_LOGS].timeout_ms);
	ATF_CHECK_STREQ("1", header(env.signals[OE_SIGNAL_LOGS].headers,
	    env.signals[OE_SIGNAL_LOGS].nheaders, "g"));
	ATF_CHECK_STREQ("http://m:1/met",
	    env.signals[OE_SIGNAL_METRICS].endpoint);
	ATF_CHECK_EQ(1, env.signals[OE_SIGNAL_METRICS].endpoint_exact);
	ATF_CHECK_EQ(500, env.signals[OE_SIGNAL_METRICS].timeout_ms);
	ATF_CHECK_STREQ("none", env.signals[OE_SIGNAL_METRICS].compression);
	ATF_CHECK_STREQ("gzip", env.signals[OE_SIGNAL_LOGS].compression);
	/* The signal's headers replace the general ones. */
	ATF_CHECK_EQ(1, env.signals[OE_SIGNAL_METRICS].nheaders);
	ATF_CHECK_STREQ("2", header(env.signals[OE_SIGNAL_METRICS].headers,
	    1, "m"));
	/* Into an exporter configuration. */
	memset(&cfg, 0, sizeof(cfg));
	oe_otlp_config_env(&cfg, &env);
	ATF_CHECK_STREQ("http://gen:4318", cfg.endpoint);
	ATF_CHECK(cfg.signals[OE_SIGNAL_LOGS].endpoint == NULL);
	ATF_CHECK_STREQ("http://m:1/met",
	    cfg.signals[OE_SIGNAL_METRICS].endpoint);
	ATF_CHECK_EQ(0.5, cfg.signals[OE_SIGNAL_METRICS].timeout);
	ATF_CHECK_EQ(1, cfg.signals[OE_SIGNAL_METRICS].has_headers);
	ATF_CHECK_STREQ("grpc", cfg.signals[OE_SIGNAL_TRACES].protocol);
	oe_env_free(&env);

	/* The command line wins over every variable. */
	req.endpoint = "http://cli:9";
	req.protocol = "http/protobuf";
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	ATF_CHECK_STREQ("http://cli:9",
	    env.signals[OE_SIGNAL_METRICS].endpoint);
	ATF_CHECK_EQ(0, env.signals[OE_SIGNAL_METRICS].endpoint_exact);
	ATF_CHECK_STREQ("http/protobuf",
	    env.signals[OE_SIGNAL_TRACES].protocol);
	oe_env_free(&env);

	/* Without the resolution, every signal inherits. */
	clean_env();
	setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://t:1/x", 1);
	oe_env_load(&env);
	memset(&cfg, 0, sizeof(cfg));
	cfg.signals[OE_SIGNAL_TRACES].endpoint = "stale";
	oe_otlp_config_signals(&cfg, &env);
	ATF_CHECK(cfg.signals[OE_SIGNAL_TRACES].endpoint == NULL);
	oe_env_free(&env);
}

/* otel.conf(5) signal blocks, and where their credentials go. */
ATF_TC_WITHOUT_HEAD(config_sysconf);
ATF_TC_BODY(config_sysconf, tc)
{
	struct oe_config_request req;
	struct oe_env env;
	const struct oe_env_signal *s;
	char err[256], conf[1024], cwd[PATH_MAX];

	clean_env();
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	write_file("gen.creds", "Authorization: general\n", 0600);
	write_file("traces.creds", "Authorization: traces\n", 0600);
	snprintf(conf, sizeof(conf),
	    "endpoint = \"http://sys:4318\";\n"
	    "headers_file = \"%s/gen.creds\";\n"
	    "host_id_file = \"\";\n"
	    "spool { directory = \"%s/nospool\"; }\n"
	    "traces { endpoint = \"http://t:1/x\"; protocol = \"grpc\";\n"
	    "    headers_file = \"%s/traces.creds\"; }\n"
	    "metrics { compression = \"none\"; timeout_ms = 1234;\n"
	    "    endpoint = \"\"; }\n"
	    "profiles { protocol = \"grpc\"; endpoint = \"http://p:2/\";\n"
	    "    headers_file = \"\"; }\n"
	    "logs { protocol = \"http/json\"; }\n", cwd, cwd, cwd);
	write_file("otel.conf", conf, 0644);
	setenv("OTELCONF_FILE", "otel.conf", 1);
	/* A signal variable sends logs elsewhere: no credentials there. */
	setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://else:1/l", 1);
	memset(&req, 0, sizeof(req));
	req.scope = "tool";
	req.system = 1;
	ATF_REQUIRE_EQ_MSG(0, oe_config_load(&env, &req, err, sizeof(err)),
	    "%s", err);
	s = &env.signals[OE_SIGNAL_LOGS];
	ATF_CHECK_STREQ("http://else:1/l", s->endpoint);
	ATF_CHECK_EQ(1, s->endpoint_exact);
	ATF_CHECK_STREQ("http/json", s->protocol);
	ATF_CHECK(header(s->headers, s->nheaders, "Authorization") == NULL);
	s = &env.signals[OE_SIGNAL_METRICS];
	ATF_CHECK_STREQ("http://sys:4318", s->endpoint);
	ATF_CHECK_EQ(0, s->endpoint_exact);
	ATF_CHECK_STREQ("none", s->compression);
	ATF_CHECK_EQ(1234, s->timeout_ms);
	ATF_CHECK_STREQ("general", header(s->headers, s->nheaders,
	    "Authorization"));
	s = &env.signals[OE_SIGNAL_TRACES];
	ATF_CHECK_STREQ("http://t:1/x", s->endpoint);
	ATF_CHECK_EQ(1, s->endpoint_exact);
	ATF_CHECK_STREQ("grpc", s->protocol);
	ATF_CHECK_STREQ("traces", header(s->headers, s->nheaders,
	    "Authorization"));
	ATF_CHECK_EQ(10000, s->timeout_ms);
	/* A block without its own headers file has the general one. */
	s = &env.signals[OE_SIGNAL_PROFILES];
	ATF_CHECK_STREQ("http://p:2/", s->endpoint);
	ATF_CHECK_STREQ("general", header(s->headers, s->nheaders,
	    "Authorization"));
	ATF_CHECK_STREQ("gzip", s->compression);
	oe_env_free(&env);

	/* A block endpoint without a headers file: the general one. */
	snprintf(conf, sizeof(conf),
	    "endpoint = \"http://sys:4318\";\n"
	    "headers_file = \"%s/gen.creds\";\n"
	    "host_id_file = \"\";\n"
	    "spool { directory = \"%s/nospool\"; }\n"
	    "logs { endpoint = \"http://l:1/l\"; }\n", cwd, cwd);
	write_file("otel2.conf", conf, 0644);
	setenv("OTELCONF_FILE", "otel2.conf", 1);
	unsetenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT");
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	s = &env.signals[OE_SIGNAL_LOGS];
	ATF_CHECK_STREQ("http://l:1/l", s->endpoint);
	ATF_CHECK_STREQ("general", header(s->headers, s->nheaders,
	    "Authorization"));
	oe_env_free(&env);
	setenv("OTELCONF_FILE", "otel.conf", 1);

	/* The general variable beats the blocks' endpoints. */
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://gen:1", 1);
	setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf", 1);
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	s = &env.signals[OE_SIGNAL_TRACES];
	ATF_CHECK_STREQ("http://gen:1", s->endpoint);
	ATF_CHECK_EQ(0, s->endpoint_exact);
	ATF_CHECK_STREQ("http/protobuf", s->protocol);
	ATF_CHECK(header(s->headers, s->nheaders, "Authorization") == NULL);
	oe_env_free(&env);

	/* The file target ignores the blocks' endpoints. */
	clean_env();
	snprintf(conf, sizeof(conf),
	    "host_id_file = \"\";\n"
	    "export { target = \"file\"; directory = \"%s\"; }\n"
	    "traces { endpoint = \"http://t:1/x\"; }\n", cwd);
	write_file("otel.conf", conf, 0644);
	setenv("OTELCONF_FILE", "otel.conf", 1);
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	ATF_CHECK(env.file_path != NULL);
	ATF_CHECK_EQ(0, env.signals[OE_SIGNAL_TRACES].endpoint_exact);
	oe_env_free(&env);
	/* A signal variable's endpoint is a target: no file. */
	setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://t:1/x", 1);
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	ATF_CHECK(env.file_path == NULL);
	ATF_CHECK_EQ(0, env.endpoint_default);
	ATF_CHECK_STREQ(OE_DEFAULT_ENDPOINT,
	    env.signals[OE_SIGNAL_LOGS].endpoint);
	oe_env_free(&env);
}

/* Malformed signal blocks are refused with the key named. */
ATF_TC_WITHOUT_HEAD(sysconf_signal_errors);
ATF_TC_BODY(sysconf_signal_errors, tc)
{
	static const struct {
		const char *conf, *msg;
	} bad[] = {
		{ "traces = 1;", "traces must be an object" },
		{ "logs { nope = 1; }", "unknown key logs.nope" },
		{ "metrics { endpoint = \"ftp://x\"; }", "metrics.endpoint" },
		{ "profiles { protocol = \"thrift\"; }",
		    "profiles.protocol \"thrift\" is not supported" },
		{ "logs { compression = \"lz4\"; }", "logs.compression" },
		{ "traces { timeout_ms = 0; }", "traces.timeout_ms 0" },
		{ "traces { headers_file = \"relative\"; }",
		    "traces.headers_file must be an absolute path" },
		{ "traces { headers_file = \"/nonexistent/creds\"; }",
		    "/nonexistent/creds" },
	};
	struct oe_sysconf sc;
	size_t i;

	clean_env();
	for (i = 0; i < nitems(bad); i++) {
		write_file("bad.conf", bad[i].conf, 0644);
		ATF_CHECK_EQ_MSG(-1, oe_sysconf_load(&sc, "", "bad.conf"),
		    "%s", bad[i].conf);
		ATF_CHECK_MSG(strstr(sc.error, bad[i].msg) != NULL,
		    "%s: %s", bad[i].conf, sc.error);
		oe_sysconf_free(&sc);
	}
	/* A well-formed block is kept; free releases it. */
	write_file("good.conf", "traces { endpoint = \"http://t:1/x\"; "
	    "timeout_ms = 5; }", 0644);
	ATF_REQUIRE_EQ(0, oe_sysconf_load(&sc, "", "good.conf"));
	ATF_CHECK_STREQ("http://t:1/x", sc.signals[OE_SIGNAL_TRACES].endpoint);
	ATF_CHECK_EQ(5, sc.signals[OE_SIGNAL_TRACES].timeout_ms);
	ATF_CHECK(sc.signals[OE_SIGNAL_LOGS].endpoint == NULL);
	oe_sysconf_free(&sc);
}

/* ---------------------------------------------------------------- */
/* One exporter, a transport per signal					*/

static const struct oe_resource *
resource(void)
{
	static struct oe_resource r;

	memset(&r, 0, sizeof(r));
	r.service_name = "svc";
	r.service_version = "1";
	return (&r);
}

static void
emit_all(struct oe_exporter *e)
{
	static char mod[] = "kernel", fn[] = "fn";
	static struct oe_frame f = { 0, mod, fn, 0, 0 };
	struct oe_event ev;
	struct oe_snapshot sn;
	struct oe_span sp;
	struct oe_profile pr;
	struct oe_profile_sample s;
	struct oe_datapoint dp = { .scalar = 5 };

	memset(&ev, 0, sizeof(ev));
	clock_gettime(CLOCK_REALTIME, &ev.ts);
	ev.profile = "p";
	ev.probe = "";
	ev.execname = "";
	ev.body = "a log line";
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
	memset(&s, 0, sizeof(s));
	s.stack = &f;
	s.nstack = 1;
	memset(&pr, 0, sizeof(pr));
	pr.profile = "p";
	pr.sample_type = "samples";
	pr.sample_unit = "count";
	pr.samples = &s;
	pr.nsamples = 1;
	ATF_REQUIRE_EQ(0, oe_profile(e, &pr));
}

/* The request of a collector at a path, or NULL. */
static const struct coll_req *
req_at(struct collector *co, const char *path)
{
	int i;

	for (i = 0; i < co->nreqs; i++)
		if (strcmp(co->reqs[i].path, path) == 0)
			return (&co->reqs[i]);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(exporter_routing);
ATF_TC_BODY(exporter_routing, tc)
{
	static const struct oe_attr gen[] = { { "X-Gen", "g" } };
	static const struct oe_attr mh[] = { { "X-M", "m" } };
	static const struct oe_attr th[] = { { "X-T", "t" } };
	struct collector a, b;
	struct gsrv c;
	struct oe_otlp_config cfg;
	struct oe_exporter *e;
	const struct coll_req *r;
	char epa[64], tep[96], pep[64];

	ATF_REQUIRE_EQ(0, coll_start(&a, 0, 0, NULL));
	ATF_REQUIRE_EQ(0, coll_start(&b, 0, 0, NULL));
	ATF_REQUIRE_EQ(0, gsrv_start(&c, 0, NULL, NULL));
	snprintf(epa, sizeof(epa), "http://127.0.0.1:%d/base", a.port);
	snprintf(tep, sizeof(tep), "http://127.0.0.1:%d/custom/traces/",
	    b.port);
	snprintf(pep, sizeof(pep), "http://127.0.0.1:%d", c.port);
	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = epa;
	cfg.protocol = "http/json";
	cfg.profile = "p";
	cfg.resource = resource();
	cfg.scope_name = "tool";
	cfg.flush_interval = 30;
	cfg.max_retries = 0;
	cfg.headers = gen;
	cfg.nheaders = 1;
	/* Metrics: the same URL, other headers and timeout. */
	cfg.signals[OE_SIGNAL_METRICS].headers = mh;
	cfg.signals[OE_SIGNAL_METRICS].nheaders = 1;
	cfg.signals[OE_SIGNAL_METRICS].has_headers = 1;
	cfg.signals[OE_SIGNAL_METRICS].timeout = 3;
	/* Traces: a signal URL as-is, http/protobuf, uncompressed. */
	cfg.signals[OE_SIGNAL_TRACES].endpoint = tep;
	cfg.signals[OE_SIGNAL_TRACES].protocol = "http/protobuf";
	cfg.signals[OE_SIGNAL_TRACES].headers = th;
	cfg.signals[OE_SIGNAL_TRACES].nheaders = 1;
	cfg.signals[OE_SIGNAL_TRACES].has_headers = 1;
	cfg.signals[OE_SIGNAL_TRACES].compression = "none";
	/* Profiles: gRPC to a third receiver. */
	cfg.signals[OE_SIGNAL_PROFILES].endpoint = pep;
	cfg.signals[OE_SIGNAL_PROFILES].protocol = "grpc";
	cfg.profiles = 1;
	ATF_REQUIRE((e = oe_otlp_new(&cfg)) != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	emit_all(e);
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	free(capture_end());
	oe_exporter_free(e);

	ATF_CHECK_EQ(2, coll_nreqs(&a));
	r = req_at(&a, "/base/v1/logs");
	ATF_REQUIRE(r != NULL);
	ATF_CHECK(r->gzipped);
	ATF_CHECK(strstr(r->headers, "X-Gen: g") != NULL);
	ATF_CHECK(strstr(r->headers, "application/json") != NULL);
	ATF_CHECK(strstr(r->body, "a log line") != NULL);
	r = req_at(&a, "/base/v1/metrics");
	ATF_REQUIRE(r != NULL);
	ATF_CHECK(strstr(r->headers, "X-M: m") != NULL);
	ATF_CHECK(strstr(r->headers, "X-Gen") == NULL);
	ATF_CHECK_EQ(1, coll_nreqs(&b));
	r = req_at(&b, "/custom/traces/");
	ATF_REQUIRE(r != NULL);
	ATF_CHECK(!r->gzipped);
	ATF_CHECK(strstr(r->headers, "X-T: t") != NULL);
	ATF_CHECK(strstr(r->headers, "application/x-protobuf") != NULL);
	ATF_REQUIRE_EQ(1, gsrv_nreqs(&c));
	ATF_CHECK(strstr(c.reqs[0].path, "ProfilesService/Export") != NULL);
	ATF_CHECK(strstr(c.reqs[0].headers, "x-gen: g\n") != NULL);
	coll_stop(&a);
	coll_stop(&b);
	gsrv_stop(&c);
}

/* From the variables through oe_exporter_open(). */
ATF_TC_WITHOUT_HEAD(exporter_from_env);
ATF_TC_BODY(exporter_from_env, tc)
{
	struct collector a, b;
	struct oe_config_request req;
	struct oe_env env;
	struct oe_otlp_config cfg;
	struct oe_exporter *e;
	char ep[64], err[256];

	clean_env();
	ATF_REQUIRE_EQ(0, coll_start(&a, 0, 0, NULL));
	ATF_REQUIRE_EQ(0, coll_start(&b, 0, 0, NULL));
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", a.port);
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", ep, 1);
	setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json", 1);
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d/only/metrics", b.port);
	setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", ep, 1);
	setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/protobuf", 1);
	setenv("OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL", "http/protobuf", 1);
	memset(&req, 0, sizeof(req));
	req.scope = "tool";
	ATF_REQUIRE_EQ(0, oe_config_load(&env, &req, err, sizeof(err)));
	memset(&cfg, 0, sizeof(cfg));
	cfg.profile = "p";
	cfg.resource = resource();
	cfg.scope_name = "tool";
	cfg.max_retries = 0;
	cfg.profiles = 1;
	ATF_REQUIRE((e = oe_exporter_open(&env, &cfg)) != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	emit_all(e);
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	free(capture_end());
	oe_exporter_free(e);
	oe_env_free(&env);
	ATF_CHECK(req_at(&a, "/v1/logs") != NULL);
	ATF_CHECK(req_at(&a, "/v1/traces") != NULL);
	ATF_CHECK(req_at(&a, "/v1development/profiles") != NULL);
	ATF_CHECK(req_at(&a, "/v1/metrics") == NULL);
	ATF_CHECK(req_at(&b, "/only/metrics") != NULL);
	coll_stop(&a);
	coll_stop(&b);
}

/*
 * Destinations are shared only when every setting matches: here each
 * signal differs from the general one in exactly one.
 */
ATF_TC_WITHOUT_HEAD(exporter_destinations);
ATF_TC_BODY(exporter_destinations, tc)
{
	static const struct oe_attr gen[] = { { "X-Gen", "g" } };
	static const struct oe_attr other[] = { { "X-Gen", "h" } };
	static const struct oe_attr two[] = { { "X-Gen", "g" },
	    { "X-B", "b" } };
	static const struct oe_attr named[] = { { "X-Name", "g" } };
	struct collector a;
	struct oe_otlp_config cfg;
	struct oe_exporter *e;
	const struct coll_req *r;
	char ep[64];
	int i;

	ATF_REQUIRE_EQ(0, coll_start(&a, 0, 0, NULL));
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d/x", a.port);
	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = ep;
	cfg.protocol = "http/json";
	cfg.resource = resource();
	cfg.scope_name = "tool";
	cfg.flush_interval = 30;
	cfg.max_retries = 0;
	cfg.headers = gen;
	cfg.nheaders = 1;
	/* Logs: the same URL, but as a signal URL (posted as-is). */
	cfg.signals[OE_SIGNAL_LOGS].endpoint = ep;
	/* Metrics: uncompressed. */
	cfg.signals[OE_SIGNAL_METRICS].compression = "none";
	/* Traces: another header value; profiles: another header count. */
	cfg.signals[OE_SIGNAL_TRACES].headers = other;
	cfg.signals[OE_SIGNAL_TRACES].nheaders = 1;
	cfg.signals[OE_SIGNAL_TRACES].has_headers = 1;
	cfg.signals[OE_SIGNAL_PROFILES].headers = two;
	cfg.signals[OE_SIGNAL_PROFILES].nheaders = 2;
	cfg.signals[OE_SIGNAL_PROFILES].has_headers = 1;
	cfg.signals[OE_SIGNAL_PROFILES].protocol = "http/protobuf";
	ATF_REQUIRE((e = oe_otlp_new(&cfg)) != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	emit_all(e);
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	free(capture_end());
	oe_exporter_free(e);
	ATF_REQUIRE((r = req_at(&a, "/x")) != NULL);
	ATF_CHECK(strstr(r->body, "a log line") != NULL);
	ATF_REQUIRE((r = req_at(&a, "/x/v1/metrics")) != NULL);
	ATF_CHECK(!r->gzipped);
	ATF_REQUIRE((r = req_at(&a, "/x/v1/traces")) != NULL);
	ATF_CHECK(strstr(r->headers, "X-Gen: h") != NULL);
	ATF_REQUIRE((r = req_at(&a, "/x/v1development/profiles")) != NULL);
	ATF_CHECK(strstr(r->headers, "X-B: b") != NULL);
	/*
	 * Settings equal but for the headers: their count, a value, a
	 * name, each makes its own destination.
	 */
	memset(cfg.signals, 0, sizeof(cfg.signals));
	cfg.signals[OE_SIGNAL_METRICS].headers = two;
	cfg.signals[OE_SIGNAL_METRICS].nheaders = 2;
	cfg.signals[OE_SIGNAL_METRICS].has_headers = 1;
	cfg.signals[OE_SIGNAL_TRACES].headers = other;
	cfg.signals[OE_SIGNAL_TRACES].nheaders = 1;
	cfg.signals[OE_SIGNAL_TRACES].has_headers = 1;
	/* (Profiles over http/json are dropped: only the set-up counts.) */
	cfg.signals[OE_SIGNAL_PROFILES].headers = named;
	cfg.signals[OE_SIGNAL_PROFILES].nheaders = 1;
	cfg.signals[OE_SIGNAL_PROFILES].has_headers = 1;
	ATF_REQUIRE((e = oe_otlp_new(&cfg)) != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	emit_all(e);
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	free(capture_end());
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(7, coll_nreqs(&a));
	for (i = 4; i < 7; i++) {
		if (strcmp(a.reqs[i].path, "/x/v1/metrics") == 0)
			ATF_CHECK(strstr(a.reqs[i].headers, "X-B: b") != NULL);
		if (strcmp(a.reqs[i].path, "/x/v1/traces") == 0)
			ATF_CHECK(strstr(a.reqs[i].headers, "X-Gen: h") != NULL);
	}
	coll_stop(&a);
}

ATF_TC_WITHOUT_HEAD(exporter_bad_signal);
ATF_TC_BODY(exporter_bad_signal, tc)
{
	struct oe_otlp_config cfg;
	struct oe_exporter *e;
	char *err;
	int n, fails, hit, ok;

	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = "http://127.0.0.1:1";
	cfg.resource = resource();
	cfg.scope_name = "tool";
	cfg.signals[OE_SIGNAL_TRACES].endpoint = "ftp://x/y";
	capture_start();
	e = oe_otlp_new(&cfg);
	err = capture_end();
	ATF_CHECK(e == NULL);
	ATF_CHECK(strstr(err, "invalid signal endpoint URL 'ftp://x/y'") !=
	    NULL);
	free(err);
	cfg.signals[OE_SIGNAL_TRACES].endpoint = NULL;
	cfg.signals[OE_SIGNAL_LOGS].protocol = "thrift";
	capture_start();
	e = oe_otlp_new(&cfg);
	err = capture_end();
	ATF_CHECK(e == NULL);
	ATF_CHECK(strstr(err, "unknown protocol \"thrift\"") != NULL);
	free(err);
	/* Allocation failures while the destinations are made. */
	cfg.signals[OE_SIGNAL_LOGS].protocol = NULL;
	cfg.signals[OE_SIGNAL_METRICS].protocol = "grpc";
	cfg.signals[OE_SIGNAL_METRICS].headers =
	    (const struct oe_attr[]){ { "a", "b" } };
	cfg.signals[OE_SIGNAL_METRICS].nheaders = 1;
	cfg.signals[OE_SIGNAL_METRICS].has_headers = 1;
	fails = 0;
	capture_start();
	for (n = 1; n < 500; n++) {
		failalloc_arm(n);
		e = oe_otlp_new(&cfg);
		hit = failalloc_hit();
		failalloc_arm(0);
		ok = e != NULL;
		if (e != NULL)
			oe_exporter_free(e);
		if (!hit) {
			ATF_CHECK(ok);
			break;
		}
		fails++;
	}
	free(capture_end());
	ATF_CHECK(fails > 5);
}

ATF_TC_WITHOUT_HEAD(url_rawpath);
ATF_TC_BODY(url_rawpath, tc)
{
	struct oe_url u;

	ATF_REQUIRE_EQ(0, oe_url_parse("http://h:1/a/b/", &u));
	ATF_CHECK_STREQ("/a/b", u.basepath);
	ATF_CHECK_STREQ("/a/b/", u.rawpath);
	ATF_REQUIRE_EQ(0, oe_url_parse("https://h", &u));
	ATF_CHECK_STREQ("/", u.rawpath);
	ATF_CHECK_STREQ("", u.basepath);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, env_signal_vars);
	ATF_TP_ADD_TC(tp, config_precedence);
	ATF_TP_ADD_TC(tp, config_sysconf);
	ATF_TP_ADD_TC(tp, sysconf_signal_errors);
	ATF_TP_ADD_TC(tp, exporter_routing);
	ATF_TP_ADD_TC(tp, exporter_from_env);
	ATF_TP_ADD_TC(tp, exporter_destinations);
	ATF_TP_ADD_TC(tp, exporter_bad_signal);
	ATF_TP_ADD_TC(tp, url_rawpath);
	return (atf_no_error());
}
