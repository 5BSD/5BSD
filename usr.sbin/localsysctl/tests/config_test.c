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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, defaults);
	ATF_TP_ADD_TC(tp, prefix_boundary);
	ATF_TP_ADD_TC(tp, per_label);
	ATF_TP_ADD_TC(tp, malformed_fails_soft);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
