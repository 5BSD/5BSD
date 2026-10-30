/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Policy-boundary tests for BSDPower.  Suspending the machine is the
 * privileged surface; these cases exercise power.conf validation and label-based operation
 * checks. They do not establish independent user or service authorization.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

/* Write UCL to a fresh 0600 temp file and load it; returns the load result. */
static int
load_text(struct powercmp_config *config, const char *text)
{
	char path[] = "/tmp/powercfg.XXXXXX";
	int fd, r;

	fd = mkstemp(path);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE((size_t)write(fd, text, strlen(text)) == strlen(text));
	(void)close(fd);
	r = powercmp_config_load(config, path);
	(void)unlink(path);
	return (r);
}

/* The compiled-in default denies every label. */
ATF_TC_WITHOUT_HEAD(default_denies_all);
ATF_TC_BODY(default_denies_all, tc)
{
	struct powercmp_config config;

	powercmp_config_defaults(&config);
	ATF_CHECK(!config.default_suspend);
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.anyone"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.5bsd.ntp"));
}

/* An explicit per-label grant allows exactly that label, nobody else. */
ATF_TC_WITHOUT_HEAD(explicit_grant_is_scoped);
ATF_TC_BODY(explicit_grant_is_scoped, tc)
{
	struct powercmp_config config;
	static const char cfg[] =
	    "default { suspend = false; }\n"
	    "clients { \"org.5bsd.ntp\" { suspend = true; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(powercmp_config_permits_suspend(&config, "org.5bsd.ntp"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.5bsd.other"));
}

/* A listed label with set=false is denied even though it is listed. */
ATF_TC_WITHOUT_HEAD(listed_but_false_is_denied);
ATF_TC_BODY(listed_but_false_is_denied, tc)
{
	struct powercmp_config config;
	static const char cfg[] =
	    "clients { \"org.5bsd.ntp\" { suspend = false; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.5bsd.ntp"));
}

/* default { suspend = true } opens it to any label (an operator override). */
ATF_TC_WITHOUT_HEAD(default_true_allows_unlisted);
ATF_TC_BODY(default_true_allows_unlisted, tc)
{
	struct powercmp_config config;
	static const char cfg[] =
	    "default { suspend = true; }\n"
	    "clients { \"org.locked\" { suspend = false; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(powercmp_config_permits_suspend(&config, "org.unlisted"));
	/* a listed set=false still wins over a permissive default */
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.locked"));
}

/* Labels match by exact string, never as a prefix/substring. */
ATF_TC_WITHOUT_HEAD(label_match_is_exact);
ATF_TC_BODY(label_match_is_exact, tc)
{
	struct powercmp_config config;
	static const char cfg[] =
	    "clients { \"org.ntp\" { suspend = true; } }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(powercmp_config_permits_suspend(&config, "org.ntp"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.ntpx"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.nt"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org."));
}

/* NULL config and NULL/empty label are denied without a crash. */
ATF_TC_WITHOUT_HEAD(null_and_empty_are_denied);
ATF_TC_BODY(null_and_empty_are_denied, tc)
{
	struct powercmp_config config;
	static const char cfg[] = "default { suspend = true; }\n";

	ATF_REQUIRE_EQ(0, load_text(&config, cfg));
	ATF_CHECK(!powercmp_config_permits_suspend(NULL, "org.any"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, NULL));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, ""));
	ATF_REQUIRE_ERRNO(EINVAL, powercmp_config_load(&config, NULL) == -1);
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.any"));
}

/* A malformed config fails soft: -1, and the config is left default-deny. */
ATF_TC_WITHOUT_HEAD(malformed_fails_soft);
ATF_TC_BODY(malformed_fails_soft, tc)
{
	struct powercmp_config config;

	ATF_CHECK_EQ(-1, load_text(&config, "clients { \"x\" = { suspend = "));
	ATF_CHECK(!config.default_suspend);
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "x"));
	/* a bogus non-boolean set value must not silently grant */
	ATF_CHECK_EQ(-1, load_text(&config,
	    "clients { \"y\" { suspend = \"yes-please\"; } }\n"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "y"));
}

/* A missing file is not an error: defaults (deny) stand. */
ATF_TC_WITHOUT_HEAD(missing_file_is_default);
ATF_TC_BODY(missing_file_is_default, tc)
{
	struct powercmp_config config;

	ATF_CHECK_EQ(0, powercmp_config_load(&config, "/nonexistent/time.conf"));
	ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.any"));
}

ATF_TC_WITHOUT_HEAD(inhibit_is_separate);
ATF_TC_BODY(inhibit_is_separate, tc)
{
 struct powercmp_config config;
 ATF_REQUIRE_EQ(0, load_text(&config,
     "clients { a { suspend = true; } b { inhibit = true; } c { inhibit = false; } }"));
 ATF_CHECK(!powercmp_config_permits_inhibit(&config, "a"));
 ATF_CHECK(powercmp_config_permits_inhibit(&config, "b"));
 ATF_CHECK(!powercmp_config_permits_suspend(&config, "b"));
 ATF_CHECK(!powercmp_config_permits_inhibit(&config, "c"));
 ATF_CHECK(!powercmp_config_permits_inhibit(&config, "unknown"));
 ATF_REQUIRE_EQ(-1, load_text(&config, "clients { a { inhibit = true; inhibit = false; } }"));
 ATF_CHECK(!powercmp_config_permits_inhibit(&config, "a"));
}


ATF_TC_WITHOUT_HEAD(reject_ambiguous_policy);
ATF_TC_BODY(reject_ambiguous_policy, tc)
{
 struct powercmp_config config;
 const char *bad[] = {
     "default { suspend = true; }; unexpected = true;",
     "default { suspend = true; suspend = false; };",
     "default { suspend = true; }; default { suspend = false; };",
     "default { suspend = 1; };",
     "default { suspend = \"yes\"; };",
     "default { suspend = null; };",
     "default { suspend = []; };",
     "default { suspend = true; unknown = false; };",
     "default { suspend = true; }; clients = [];",
     "clients { \"org.test\" { suspend = true; }; \"org.test\" { suspend = false; }; };",
     "clients { \"org.test\" { suspend = true; unknown = false; }; };",
     "clients { \"org.test\\u0000suffix\" { suspend = true; }; };",
     "\"default\\u0000suffix\" { suspend = true; };",
     "default { \"suspend\\u0000suffix\" = true; };",
     "clients { \"org.test\" { suspend = true; }; \"bad name\" { suspend = true; }; };",
 };
 (void)tc;
 for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
     ATF_REQUIRE_EQ(0, load_text(&config, "default { suspend = true; };"));
     ATF_CHECK_MSG(load_text(&config, bad[i]) == -1,
         "accepted malformed policy: %s", bad[i]);
     ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.test"));
     ATF_CHECK(!powercmp_config_permits_suspend(&config, "unlisted"));
     ATF_CHECK_EQ(0, config.nclients);
 }
}

ATF_TC_WITHOUT_HEAD(no_external_policy);
ATF_TC_BODY(no_external_policy, tc)
{
 struct powercmp_config config;
 FILE *file;
 (void)tc;
 file = fopen("external-policy.ucl", "w");
 ATF_REQUIRE(file != NULL);
 ATF_REQUIRE(fputs("default { suspend = true; };", file) >= 0);
 ATF_REQUIRE_EQ(0, fclose(file));
 ATF_CHECK_EQ(-1, load_text(&config, ".include \"external-policy.ucl\"\n"));
 ATF_CHECK(!powercmp_config_permits_suspend(&config, "org.test"));
 ATF_CHECK_EQ(0, unlink("external-policy.ucl"));
}


static int
policy_fd(const char *text, size_t length)
{
	char path[] = "policy.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, unlink(path));
	ATF_REQUIRE_EQ((ssize_t)length, write(fd, text, length));
	return (fd);
}

ATF_TC_WITHOUT_HEAD(descriptor_policy);
ATF_TC_BODY(descriptor_policy, tc)
{
	const char valid[] = "default { suspend = true; };";
	const char raw_nul[] = "default { suspend = true; };\0ignored";
	struct powercmp_config config;
	char *text;
	int fd, fds[2];

	(void)tc;
	fd = policy_fd(valid, sizeof(valid) - 1);
	/* Input offset is at EOF; policy must still be read from offset zero. */
	ATF_REQUIRE_EQ(0, powercmp_config_load_fd(&config, fd));
	ATF_REQUIRE(powercmp_config_permits_suspend(&config, "org.test"));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	fd = policy_fd(raw_nul, sizeof(raw_nul) - 1);
	ATF_REQUIRE_EQ(-1, powercmp_config_load_fd(&config, fd));
	ATF_REQUIRE(!powercmp_config_permits_suspend(&config, "org.test"));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	fd = policy_fd(valid, sizeof(valid) - 1);
	ATF_REQUIRE_EQ(0, fchmod(fd, 0660));
	ATF_REQUIRE_ERRNO(EPERM, powercmp_config_load_fd(&config, fd) == -1);
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	ATF_REQUIRE_EQ(0, pipe(fds));
	ATF_REQUIRE_ERRNO(EINVAL, powercmp_config_load_fd(&config, fds[0]) == -1);
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fds[0], F_GETFD) == -1);
	close(fds[1]);
	text = malloc(POWERCMP_CONFIG_FILE_MAX + 1);
	ATF_REQUIRE(text != NULL);
	memset(text, ' ', POWERCMP_CONFIG_FILE_MAX + 1);
	memcpy(text, valid, sizeof(valid) - 1);
	fd = policy_fd(text, POWERCMP_CONFIG_FILE_MAX);
	ATF_REQUIRE_EQ(0, powercmp_config_load_fd(&config, fd));
	ATF_REQUIRE(powercmp_config_permits_suspend(&config, "org.test"));
	fd = policy_fd(text, POWERCMP_CONFIG_FILE_MAX + 1);
	ATF_REQUIRE_ERRNO(EFBIG, powercmp_config_load_fd(&config, fd) == -1);
	ATF_REQUIRE(!powercmp_config_permits_suspend(&config, "org.test"));
	free(text);
}

ATF_TC_WITHOUT_HEAD(confined_policy);
ATF_TC_BODY(confined_policy, tc)
{
	const char valid[] = "clients { org.test { suspend = true; }; };";
	struct powercmp_config config;
	cap_rights_t rights;
	int fd;

	(void)tc;
	fd = policy_fd(valid, sizeof(valid) - 1);
	cap_rights_init(&rights, CAP_PREAD, CAP_FSTAT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, cap_enter());
	ATF_REQUIRE_EQ(0, powercmp_config_load_fd(&config, fd));
	ATF_REQUIRE(powercmp_config_permits_suspend(&config, "org.test"));
	ATF_REQUIRE(!powercmp_config_permits_suspend(&config, "org.other"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, inhibit_is_separate);
	ATF_TP_ADD_TC(tp, descriptor_policy);
	ATF_TP_ADD_TC(tp, confined_policy);
	ATF_TP_ADD_TC(tp, reject_ambiguous_policy);
	ATF_TP_ADD_TC(tp, no_external_policy);
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
