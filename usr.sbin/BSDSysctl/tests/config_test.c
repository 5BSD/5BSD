/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

/* Write text to a fresh 0600 temp file and load it; returns the load result. */
static int
load_text(struct sysctlcmp_config *config, const char *text)
{
	char path[] = "/tmp/sysctlcfg.XXXXXX";
	int fd, r;

	fd = mkstemp(path);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE((size_t)write(fd, text, strlen(text)) == strlen(text));
	close(fd);
	r = sysctlcmp_config_load(config, path);
	(void)unlink(path);
	return (r);
}

ATF_TC_WITHOUT_HEAD(defaults);
ATF_TC_BODY(defaults, tc)
{
	struct sysctlcmp_config config;

	sysctlcmp_config_defaults(&config);
	/* Safe read set present, no writes, no clients. */
	ATF_CHECK(config.default_acl.nread > 0);
	ATF_CHECK_EQ(0, config.default_acl.nwrite);
	ATF_CHECK_EQ(0, config.nclients);
	ATF_CHECK(sysctlcmp_config_permits(&config, "org.any", "kern.ostype",
	    false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org.any", "kern.ostype",
	    true));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org.any", "net.inet.ip",
	    false));
}

ATF_TC_WITHOUT_HEAD(prefix_boundary);
ATF_TC_BODY(prefix_boundary, tc)
{
	struct sysctlcmp_config config;

	sysctlcmp_config_defaults(&config);
	/* "kern.ostype" prefix matches itself and children, not "kern.ostypeX". */
	ATF_CHECK(sysctlcmp_config_permits(&config, "x", "kern.ostype", false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "kern.ostypex",
	    false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "kern.ostyp", false));
}

ATF_TC_WITHOUT_HEAD(per_label);
ATF_TC_BODY(per_label, tc)
{
	struct sysctlcmp_config config;
	static const char cfg[] =
	    "default { read = [\"kern.ostype\"]; write = []; }\n"
	    "clients {\n"
	    "  \"org.x\" { read = [\"net\"]; write = [\"net.inet.tcp\"]; }\n"
	    "}\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	/* Listed label uses its own ACL, replacing (not merging) the default. */
	ATF_CHECK(sysctlcmp_config_permits(&config, "org.x", "net.inet.ip",
	    false));
	ATF_CHECK(sysctlcmp_config_permits(&config, "org.x",
	    "net.inet.tcp.rfc1323", true));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org.x", "net.inet.udp",
	    true));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org.x", "kern.ostype",
	    false));
	/* Unlisted label falls back to default. */
	ATF_CHECK(sysctlcmp_config_permits(&config, "org.other", "kern.ostype",
	    false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org.other", "net.inet.ip",
	    false));
}

ATF_TC_WITHOUT_HEAD(malformed_fails_soft);
ATF_TC_BODY(malformed_fails_soft, tc)
{
	struct sysctlcmp_config config;

	/* Unknown key in an acl object is rejected; defaults are restored. */
	ATF_CHECK_ERRNO(EINVAL, load_text(&config,
	    "default { bogus = [\"x\"]; }\n") == -1);
	ATF_CHECK(config.default_acl.nread > 0);
	ATF_CHECK_EQ(0, config.default_acl.nwrite);
	ATF_CHECK(sysctlcmp_config_permits(&config, "x", "kern.ostype", false));

	/* A non-array read value is rejected. */
	ATF_CHECK_ERRNO(EINVAL, load_text(&config,
	    "default { read = \"kern\"; }\n") == -1);
	ATF_CHECK(config.default_acl.nread > 0);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct sysctlcmp_config config;

	sysctlcmp_config_defaults(&config);
	ATF_CHECK(!sysctlcmp_config_permits(NULL, "x", "kern.ostype", false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", NULL, false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "", false));
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_config_load(NULL, "/x") == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_config_load(&config, NULL) == -1);
	/* Missing file is the defaults case, not an error. */
	ATF_CHECK_EQ(0, sysctlcmp_config_load(&config,
	    "/nonexistent/sysctl.conf"));
}

/*
 * Adversarial policy tests.  BSDSysctl is an ambient provider doing
 * unrestricted __sysctlbyname(2); the per-label ACL is the ONLY security
 * boundary, so these hammer the ways a caller might try to slip past it.
 */

/* A read grant NEVER confers write: the two lists are independent. */
ATF_TC_WITHOUT_HEAD(write_not_implied_by_read);
ATF_TC_BODY(write_not_implied_by_read, tc)
{
	struct sysctlcmp_config config;
	static const char cfg[] =
	    "default { read = [\"kern\"]; write = []; }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(sysctlcmp_config_permits(&config, "x", "kern.maxproc", false));
	/* same name, write: denied -- read must not imply write */
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "kern.maxproc", true));
}

/* The default policy denies every write (default-deny on the dangerous op). */
ATF_TC_WITHOUT_HEAD(default_denies_writes);
ATF_TC_BODY(default_denies_writes, tc)
{
	struct sysctlcmp_config config;

	sysctlcmp_config_defaults(&config);
	ATF_CHECK_EQ(0, config.default_acl.nwrite);
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "kern.ostype", true));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "hw.physmem", true));
}

/* A client label matches by exact string, never as a prefix/substring: a
 * config entry for "org.x" must not leak to "org.xy", "org.", or "org". */
ATF_TC_WITHOUT_HEAD(label_match_exact_not_prefix);
ATF_TC_BODY(label_match_exact_not_prefix, tc)
{
	struct sysctlcmp_config config;
	static const char cfg[] =
	    "default { read = []; write = []; }\n"
	    "clients { \"org.x\" { read = [\"net\"]; write = []; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(sysctlcmp_config_permits(&config, "org.x", "net.inet", false));
	/* neighbours of the label get the (empty) default, not org.x's grant */
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org.xy", "net.inet",
	    false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org.", "net.inet",
	    false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "org", "net.inet", false));
}

/* NULL config, and NULL/empty name, are all denied -- never a crash or a
 * default-allow. */
ATF_TC_WITHOUT_HEAD(null_and_empty_are_denied);
ATF_TC_BODY(null_and_empty_are_denied, tc)
{
	struct sysctlcmp_config config;

	sysctlcmp_config_defaults(&config);
	ATF_CHECK(!sysctlcmp_config_permits(NULL, "x", "kern.ostype", false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "", false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", NULL, false));
	/* a NULL label is allowed and simply uses the default ACL */
	ATF_CHECK(sysctlcmp_config_permits(&config, NULL, "kern.ostype", false));
}

/* A grant only reaches a child across a dot: "net" grants "net.inet" but not
 * "network"; an exact-name grant "hw.ncpu" denies "hw.ncpuset". */
ATF_TC_WITHOUT_HEAD(grant_stops_at_dot_boundary);
ATF_TC_BODY(grant_stops_at_dot_boundary, tc)
{
	struct sysctlcmp_config config;
	static const char cfg[] =
	    "default { read = [\"net\", \"hw.ncpu\"]; write = []; }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(sysctlcmp_config_permits(&config, "x", "net", false));
	ATF_CHECK(sysctlcmp_config_permits(&config, "x", "net.inet.tcp", false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "network", false));
	ATF_CHECK(sysctlcmp_config_permits(&config, "x", "hw.ncpu", false));
	ATF_CHECK(!sysctlcmp_config_permits(&config, "x", "hw.ncpuset", false));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, defaults);
	ATF_TP_ADD_TC(tp, prefix_boundary);
	ATF_TP_ADD_TC(tp, per_label);
	ATF_TP_ADD_TC(tp, malformed_fails_soft);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, write_not_implied_by_read);
	ATF_TP_ADD_TC(tp, default_denies_writes);
	ATF_TP_ADD_TC(tp, label_match_exact_not_prefix);
	ATF_TP_ADD_TC(tp, null_and_empty_are_denied);
	ATF_TP_ADD_TC(tp, grant_stops_at_dot_boundary);
	return (atf_no_error());
}
