/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Allocation-failure sweep over the otel.conf(5) loader: every
 * allocation made by oe_sysconf.c is failed in turn, and each failure
 * must surface as a clean "out of memory" error with no leak or crash.
 * This program links a second copy of oe_sysconf.c compiled with
 * failalloc.h force-included.
 */

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_sysconf.h"

extern long failalloc_countdown;
extern long failalloc_failures;

#define	SWEEP_MAX	10000

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
	long n;
	int r;

	write_config();
	unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	setenv("OTEL_RESOURCE_ATTRIBUTES", "a=env", 1);
	unsetenv("OTEL_EXPORTER_OTLP_HEADERS");
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "", "local.conf"), 0, "%s",
	    sc.error);
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
		ATF_CHECK_EQ(r, -1);
		oe_env_free(&env);
	}
	ATF_REQUIRE(n > 4);
	oe_sysconf_free(&sc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, load_sweep);
	ATF_TP_ADD_TC(tp, init_sweep);
	ATF_TP_ADD_TC(tp, env_sweep);
	return (atf_no_error());
}
