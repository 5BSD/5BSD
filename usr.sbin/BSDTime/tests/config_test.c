/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Policy-boundary tests for BSDTime.  Stepping/slewing the clock is the
 * privileged surface; these cases exercise time.conf validation and label-based operation
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
	ATF_REQUIRE_ERRNO(EINVAL, timecmp_config_load(&config, NULL) == -1);
	ATF_CHECK(!timecmp_config_permits_set(&config, "org.any"));
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
	ATF_CHECK_EQ(-1, load_text(&config,
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


ATF_TC_WITHOUT_HEAD(reject_ambiguous_policy);
ATF_TC_BODY(reject_ambiguous_policy, tc)
{
 struct timecmp_config config;
 const char *bad[] = {
     "default { set = true; }; unexpected = true;",
     "default { set = true; set = false; };",
     "default { set = true; }; default { set = false; };",
     "default { set = 1; };",
     "default { set = \"yes\"; };",
     "default { set = null; };",
     "default { set = []; };",
     "default { set = true; unknown = false; };",
     "default { set = true; }; clients = [];",
     "clients { \"org.test\" { set = true; }; \"org.test\" { set = false; }; };",
     "clients { \"org.test\" { set = true; unknown = false; }; };",
     "clients { \"org.test\\u0000suffix\" { set = true; }; };",
     "\"default\\u0000suffix\" { set = true; };",
     "default { \"set\\u0000suffix\" = true; };",
     "clients { \"org.test\" { set = true; }; \"bad name\" { set = true; }; };",
 };
 (void)tc;
 for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
     ATF_REQUIRE_EQ(0, load_text(&config, "default { set = true; };"));
     ATF_CHECK_MSG(load_text(&config, bad[i]) == -1,
         "accepted malformed policy: %s", bad[i]);
     ATF_CHECK(!timecmp_config_permits_set(&config, "org.test"));
     ATF_CHECK(!timecmp_config_permits_set(&config, "unlisted"));
     ATF_CHECK_EQ(0, config.nclients);
 }
}

ATF_TC_WITHOUT_HEAD(no_external_policy);
ATF_TC_BODY(no_external_policy, tc)
{
 struct timecmp_config config;
 FILE *file;
 (void)tc;
 file = fopen("external-policy.ucl", "w");
 ATF_REQUIRE(file != NULL);
 ATF_REQUIRE(fputs("default { set = true; };", file) >= 0);
 ATF_REQUIRE_EQ(0, fclose(file));
 ATF_CHECK_EQ(-1, load_text(&config, ".include \"external-policy.ucl\"\n"));
 ATF_CHECK(!timecmp_config_permits_set(&config, "org.test"));
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
	const char valid[] = "default { set = true; };";
	const char raw_nul[] = "default { set = true; };\0ignored";
	struct timecmp_config config;
	char *text;
	int fd, fds[2];

	(void)tc;
	fd = policy_fd(valid, sizeof(valid) - 1);
	/* Input offset is at EOF; policy must still be read from offset zero. */
	ATF_REQUIRE_EQ(0, timecmp_config_load_fd(&config, fd));
	ATF_REQUIRE(timecmp_config_permits_set(&config, "org.test"));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	fd = policy_fd(raw_nul, sizeof(raw_nul) - 1);
	ATF_REQUIRE_EQ(-1, timecmp_config_load_fd(&config, fd));
	ATF_REQUIRE(!timecmp_config_permits_set(&config, "org.test"));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	fd = policy_fd(valid, sizeof(valid) - 1);
	ATF_REQUIRE_EQ(0, fchmod(fd, 0660));
	ATF_REQUIRE_ERRNO(EPERM, timecmp_config_load_fd(&config, fd) == -1);
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	ATF_REQUIRE_EQ(0, pipe(fds));
	ATF_REQUIRE_ERRNO(EINVAL, timecmp_config_load_fd(&config, fds[0]) == -1);
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fds[0], F_GETFD) == -1);
	close(fds[1]);
	text = malloc(TIMECMP_CONFIG_FILE_MAX + 1);
	ATF_REQUIRE(text != NULL);
	memset(text, ' ', TIMECMP_CONFIG_FILE_MAX + 1);
	memcpy(text, valid, sizeof(valid) - 1);
	fd = policy_fd(text, TIMECMP_CONFIG_FILE_MAX);
	ATF_REQUIRE_EQ(0, timecmp_config_load_fd(&config, fd));
	ATF_REQUIRE(timecmp_config_permits_set(&config, "org.test"));
	fd = policy_fd(text, TIMECMP_CONFIG_FILE_MAX + 1);
	ATF_REQUIRE_ERRNO(EFBIG, timecmp_config_load_fd(&config, fd) == -1);
	ATF_REQUIRE(!timecmp_config_permits_set(&config, "org.test"));
	free(text);
}

ATF_TC_WITHOUT_HEAD(confined_policy);
ATF_TC_BODY(confined_policy, tc)
{
	const char valid[] = "clients { org.test { set = true; }; };";
	struct timecmp_config config;
	cap_rights_t rights;
	int fd;

	(void)tc;
	fd = policy_fd(valid, sizeof(valid) - 1);
	cap_rights_init(&rights, CAP_PREAD, CAP_FSTAT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, cap_enter());
	ATF_REQUIRE_EQ(0, timecmp_config_load_fd(&config, fd));
	ATF_REQUIRE(timecmp_config_permits_set(&config, "org.test"));
	ATF_REQUIRE(!timecmp_config_permits_set(&config, "org.other"));
}

ATF_TP_ADD_TCS(tp)
{

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
