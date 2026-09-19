/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Policy-boundary tests for BSDTime.  Stepping/slewing the clock is the
 * privileged surface; the per-label time.conf ACL is the ONLY thing standing
 * between a caller and CLOCK_REALTIME, so these hammer the deny path.
 */
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

/* Write UCL to a fresh 0600 temp file and load it; returns the load result. */
static int
load_text(struct timecmp_config *config, const char *text)
{
	char path[] = "/tmp/timecfg.XXXXXX";
	int fd, r;

	fd = mkstemp(path);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE((size_t)write(fd, text, strlen(text)) == strlen(text));
	(void)close(fd);
	r = timecmp_config_load(config, path);
	(void)unlink(path);
	return (r);
}

/* The compiled-in default denies every label. */
ATF_TC_WITHOUT_HEAD(default_denies_all);
ATF_TC_BODY(default_denies_all, tc)
{
	struct timecmp_config config;

	timecmp_config_defaults(&config);
	ATF_CHECK(!config.default_set);
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.anyone"));
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.5bsd.ntp"));
}

/* An explicit per-label grant allows exactly that label, nobody else. */
ATF_TC_WITHOUT_HEAD(explicit_grant_is_scoped);
ATF_TC_BODY(explicit_grant_is_scoped, tc)
{
	struct timecmp_config config;
	static const char cfg[] =
	    "default { set = false; }\n"
	    "clients { \"org.5bsd.ntp\" { set = true; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(timecmp_config_permits_set(&config, "org.5bsd.ntp"));
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.5bsd.other"));
}

/* A listed label with set=false is denied even though it is listed. */
ATF_TC_WITHOUT_HEAD(listed_but_false_is_denied);
ATF_TC_BODY(listed_but_false_is_denied, tc)
{
	struct timecmp_config config;
	static const char cfg[] =
	    "clients { \"org.5bsd.ntp\" { set = false; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.5bsd.ntp"));
}

/* default { set = true } opens it to any label (an operator override). */
ATF_TC_WITHOUT_HEAD(default_true_allows_unlisted);
ATF_TC_BODY(default_true_allows_unlisted, tc)
{
	struct timecmp_config config;
	static const char cfg[] =
	    "default { set = true; }\n"
	    "clients { \"org.locked\" { set = false; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(timecmp_config_permits_set(&config, "org.unlisted"));
	/* a listed set=false still wins over a permissive default */
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.locked"));
}

/* Labels match by exact string, never as a prefix/substring. */
ATF_TC_WITHOUT_HEAD(label_match_is_exact);
ATF_TC_BODY(label_match_is_exact, tc)
{
	struct timecmp_config config;
	static const char cfg[] =
	    "clients { \"org.ntp\" { set = true; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(timecmp_config_permits_set(&config, "org.ntp"));
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.ntpx"));
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.nt"));
	ATF_CHECK(!timecmp_config_permits_set(&config, "org."));
}

/* NULL config and NULL/empty label are denied without a crash. */
ATF_TC_WITHOUT_HEAD(null_and_empty_are_denied);
ATF_TC_BODY(null_and_empty_are_denied, tc)
{
	struct timecmp_config config;
	static const char cfg[] = "default { set = true; }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(!timecmp_config_permits_set(NULL, "org.any"));
	ATF_CHECK(!timecmp_config_permits_set(&config, NULL));
	ATF_CHECK(!timecmp_config_permits_set(&config, ""));
}

/* A malformed config fails soft: -1, and the config is left default-deny. */
ATF_TC_WITHOUT_HEAD(malformed_fails_soft);
ATF_TC_BODY(malformed_fails_soft, tc)
{
	struct timecmp_config config;

	ATF_CHECK_EQ(-1, load_text(&config, "clients { \"x\" = { set = "));
	ATF_CHECK(!config.default_set);
	ATF_CHECK(!timecmp_config_permits_set(&config, "x"));
	/* a bogus non-boolean set value must not silently grant */
	ATF_CHECK_EQ(0, load_text(&config,
	    "clients { \"y\" { set = \"yes-please\"; } }\n"));
	ATF_CHECK(!timecmp_config_permits_set(&config, "y"));
}

/* A missing file is not an error: defaults (deny) stand. */
ATF_TC_WITHOUT_HEAD(missing_file_is_default);
ATF_TC_BODY(missing_file_is_default, tc)
{
	struct timecmp_config config;

	ATF_CHECK_EQ(0, timecmp_config_load(&config, "/nonexistent/time.conf"));
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.any"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, default_denies_all);
	ATF_TP_ADD_TC(tp, explicit_grant_is_scoped);
	ATF_TP_ADD_TC(tp, listed_but_false_is_denied);
	ATF_TP_ADD_TC(tp, default_true_allows_unlisted);
	ATF_TP_ADD_TC(tp, label_match_is_exact);
	ATF_TP_ADD_TC(tp, null_and_empty_are_denied);
	ATF_TP_ADD_TC(tp, malformed_fails_soft);
	ATF_TP_ADD_TC(tp, missing_file_is_default);
	return (atf_no_error());
}
