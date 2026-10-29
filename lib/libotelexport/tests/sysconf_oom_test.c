/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Allocation-failure sweep over the otel.conf(5) loader and the
 * configuration path built on it: every allocation made by the library
 * is failed in turn, and each failure must surface as a clean "out of
 * memory" error with no leak or crash.  failalloc.c wraps the
 * allocators at link time, so the library is tested as built.
 */

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_sysconf.h"

#include "failalloc.h"

#define	SWEEP_MAX	10000
#define	COUNT_START	1000000

/*
 * Allocations made by oe_env_load() for the current environment.  A
 * failure among them drops the variable with a warning (the documented
 * treatment of an unusable OTEL_* value), so the load still succeeds.
 */
static long
env_allocations(void)
{
	struct oe_env env;
	long used;

	failalloc_countdown = COUNT_START;
	oe_env_load(&env);
	used = COUNT_START - failalloc_countdown;
	failalloc_countdown = -1;
	oe_env_free(&env);
	return (used);
}

static void
write_file(const char *path, const char *text, mode_t mode)
{
	FILE *f;

	f = fopen(path, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(text, f) >= 0);
	ATF_REQUIRE(fclose(f) == 0);
	ATF_REQUIRE(chmod(path, mode) == 0);
}

static void
write_config(void)
{
	char conf[2048], cwd[256];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	write_file("creds", "Authorization: Bearer x\nX-Two: y\n", 0600);
	write_file("hostid", "0f9a6c1e-1111-2222-3333-444455556666\n", 0644);
	snprintf(conf, sizeof(conf),
	    "endpoint = \"http://collector:4318\";\n"
	    "protocol = \"http/json\";\n"
	    "compression = \"none\";\n"
	    "headers_file = \"%s/creds\";\n"
	    "host_id_file = \"%s/hostid\";\n"
	    "resource { a = \"1\"; b = \"2\"; c = \"\"; }\n"
	    "spool { directory = \"/var/db/otel\"; }\n"
	    "agent {\n"
	    "  listen = \"127.0.0.1:4319\";\n"
	    "  upstream = \"https://up:4318\";\n"
	    "  upstream_protocol = \"grpc\";\n"
	    "  headers_file = \"/etc/otel/up\";\n"
	    "  log_level = \"warn\";\n"
	    "  tail = [\"/var/log/a\", \"/var/log/b\"];\n"
	    "}\n", cwd, cwd);
	write_file("local.conf", conf, 0644);
	/* The defaults layer replaces an attribute and the tail list. */
	write_file("defaults.conf", "resource { a = \"0\"; c = \"x\"; }\n"
	    "agent { tail = [\"/var/log/old\"]; }\n", 0644);
}

ATF_TC_WITHOUT_HEAD(load_sweep);
ATF_TC_BODY(load_sweep, tc)
{
	struct oe_sysconf sc;
	long n;
	int r;

	write_config();
	for (n = 0; n < SWEEP_MAX; n++) {
		failalloc_failures = 0;
		failalloc_countdown = n;
		r = oe_sysconf_load(&sc, "defaults.conf", "local.conf");
		failalloc_countdown = -1;
		if (failalloc_failures == 0) {
			ATF_REQUIRE_EQ_MSG(r, 0, "%s", sc.error);
			ATF_CHECK_EQ(sc.nheaders, 2);
			ATF_CHECK_EQ(sc.nresource_attrs, 3);
			ATF_CHECK_EQ(sc.nagent_tail, 2);
			oe_sysconf_free(&sc);
			break;
		}
		ATF_CHECK_EQ(r, -1);
		ATF_CHECK_MSG(strstr(sc.error, "out of memory") != NULL,
		    "allocation %ld: \"%s\"", n, sc.error);
		oe_sysconf_free(&sc);
	}
	ATF_REQUIRE_MSG(n > 20 && n < SWEEP_MAX, "sweep ended at %ld", n);
}

ATF_TC_WITHOUT_HEAD(init_sweep);
ATF_TC_BODY(init_sweep, tc)
{
	struct oe_sysconf sc;
	long n;
	int r;

	for (n = 0; n < SWEEP_MAX; n++) {
		failalloc_failures = 0;
		failalloc_countdown = n;
		r = oe_sysconf_init(&sc);
		failalloc_countdown = -1;
		if (failalloc_failures == 0) {
			ATF_REQUIRE_EQ(r, 0);
			oe_sysconf_free(&sc);
			break;
		}
		ATF_REQUIRE_EQ(r, -1);
		ATF_CHECK_STREQ(sc.error, "out of memory");
		ATF_CHECK(sc.endpoint == NULL && sc.agent_log_level == NULL);
	}
	ATF_REQUIRE(n >= 11);
}

ATF_TC_WITHOUT_HEAD(env_sweep);
ATF_TC_BODY(env_sweep, tc)
{
	struct oe_sysconf sc;
	struct oe_env env;
	long k, n;
	int r;

	write_config();
	unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	setenv("OTEL_RESOURCE_ATTRIBUTES", "a=env", 1);
	unsetenv("OTEL_EXPORTER_OTLP_HEADERS");
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "", "local.conf"), 0, "%s",
	    sc.error);
	k = env_allocations();
	ATF_REQUIRE(k > 0);
	for (n = 0; n < SWEEP_MAX; n++) {
		failalloc_failures = 0;
		failalloc_countdown = n;
		r = oe_env_load_system(&env, &sc, NULL);
		failalloc_countdown = -1;
		if (failalloc_failures == 0) {
			ATF_REQUIRE_EQ(r, 0);
			ATF_CHECK_EQ(env.nresource_attrs, 3);
			ATF_CHECK_EQ(env.nheaders, 2);
			oe_env_free(&env);
			break;
		}
		/* The environment layer degrades; the merge must fail. */
		ATF_CHECK_EQ(r, n < k ? 0 : -1);
		oe_env_free(&env);
	}
	ATF_REQUIRE(n > 4);
	oe_sysconf_free(&sc);
}

/* oe_config_load(): the one configuration path of every tool. */
ATF_TC_WITHOUT_HEAD(config_sweep);
ATF_TC_BODY(config_sweep, tc)
{
	struct oe_config_request req;
	struct oe_env env;
	struct oe_sysconf sc;
	char conf[512], cwd[256], err[600];
	long k, m, n;
	int r;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("spool", 0700) == 0);
	write_file("creds", "Authorization: Bearer x\n", 0600);
	snprintf(conf, sizeof(conf), "endpoint = \"http://collector:4318\";\n"
	    "headers_file = \"%s/creds\";\nhost_id_file = \"\";\n"
	    "resource { a = \"1\"; }\n"
	    "spool { directory = \"%s/spool\"; }\n", cwd, cwd);
	write_file("local.conf", conf, 0644);
	setenv("OTELCONF_DEFAULTS", "", 1);
	setenv("OTELCONF_FILE", "local.conf", 1);
	setenv("OTEL_RESOURCE_ATTRIBUTES", "b=2", 1);
	memset(&req, 0, sizeof(req));
	req.scope = "tool";
	req.system = 1;
	/* Allocation order: the object, otel.conf (m), environment (k). */
	failalloc_countdown = COUNT_START;
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, NULL, NULL), 0);
	m = COUNT_START - failalloc_countdown;
	failalloc_countdown = -1;
	oe_sysconf_free(&sc);
	k = env_allocations();
	for (n = 0; n < SWEEP_MAX; n++) {
		failalloc_failures = 0;
		failalloc_countdown = n;
		r = oe_config_load(&env, &req, err, sizeof(err));
		failalloc_countdown = -1;
		if (failalloc_failures == 0) {
			ATF_REQUIRE_EQ_MSG(r, 0, "%s", err);
			ATF_CHECK(env.spool_path != NULL);
			ATF_CHECK_EQ(env.nresource_attrs, 2);
			ATF_CHECK_EQ(env.nheaders, 1);
			oe_env_free(&env);
			break;
		}
		if (n > m && n <= m + k) {
			ATF_CHECK_EQ(r, 0);	/* environment degraded */
			oe_env_free(&env);
			continue;
		}
		ATF_CHECK_EQ(r, -1);
		ATF_CHECK_MSG(strstr(err, "out of memory") != NULL,
		    "allocation %ld: \"%s\"", n, err);
		/* A failed load leaves env empty and safe to free. */
		ATF_CHECK(env.sysconf == NULL && env.spool_buf == NULL);
		oe_env_free(&env);
	}
	ATF_REQUIRE_MSG(n > 10 && n < SWEEP_MAX, "sweep ended at %ld", n);
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, load_sweep);
	ATF_TP_ADD_TC(tp, init_sweep);
	ATF_TP_ADD_TC(tp, env_sweep);
	ATF_TP_ADD_TC(tp, config_sweep);
	return (atf_no_error());
}
