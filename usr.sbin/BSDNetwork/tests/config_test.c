/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Pure-unit regression suite for the bsdnetwork(8) per-client policy
 * configuration (N1) — the per-LABEL table that scopes what each session may
 * do once the coarse identity.rights gate is reduced to the ADMIN bypass.
 * These cases link the daemon's config object directly; no capability plane,
 * no network, no privilege is required, so they run in any environment.
 */

#include <sys/stat.h>

#include <sys/types.h>
#include <sys/capsicum.h>
#include <fcntl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

/*
 * Write content to a fresh 0600 file owned by the current euid (satisfying
 * networkcmp_config_load's regular/owner/not-group-or-other-writable checks)
 * and return its path in a caller-owned static buffer.
 */
static const char *
write_conf(const char *content)
{
	static char path[64];
	int fd;
	size_t len;

	strlcpy(path, "conf.XXXXXX", sizeof(path));
	fd = mkstemp(path);
	ATF_REQUIRE_MSG(fd >= 0, "mkstemp: %s", strerror(errno));
	len = strlen(content);
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, content, len));
	ATF_REQUIRE_EQ(0, close(fd));
	return (path);
}

static void
check_shipped_default(const struct networkcmp_policy *policy)
{

	ATF_CHECK(policy->ipv4);
	ATF_CHECK(policy->ipv6);
	ATF_CHECK(policy->allow_connect);
	ATF_CHECK(policy->allow_udp);
	ATF_CHECK(policy->resolve);
	ATF_CHECK(!policy->allow_internal);
	ATF_CHECK_EQ(16, policy->max_results);
}

/*
 * The compiled-in default equals today's effective non-admin policy: outbound
 * resolve/connect/udp over both families allowed, internal ranges denied.
 * Nothing regresses when no config file ships.
 */
ATF_TC_WITHOUT_HEAD(compiled_default_matches_historical_grant);
ATF_TC_BODY(compiled_default_matches_historical_grant, tc)
{
	struct networkcmp_config config;

	networkcmp_config_defaults(&config);
	ATF_CHECK_EQ(0, (int)config.nclients);
	check_shipped_default(&config.default_policy);
}

/*
 * A clients{} entry names only the dimensions it overrides; unnamed
 * dimensions inherit from default.  The lookup for a listed label returns the
 * overridden policy and reports it as listed.
 */
ATF_TC_WITHOUT_HEAD(client_entry_overrides_and_inherits);
ATF_TC_BODY(client_entry_overrides_and_inherits, tc)
{
	struct networkcmp_config config;
	const struct networkcmp_policy *policy;
	bool listed;

	ATF_REQUIRE_EQ(0, networkcmp_config_parse(
	    "default { resolve = true; connect = true; udp = true;\n"
	    "  inet4 = true; inet6 = true; internal = false; }\n"
	    "clients {\n"
	    "  \"org.test.render\" { connect = false; udp = false; }\n"
	    "  \"org.test.metrics\" { internal = true; }\n"
	    "}\n", &config));
	ATF_REQUIRE_EQ(2, (int)config.nclients);
	policy = networkcmp_config_lookup(&config, "org.test.render", &listed);
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(listed);
	/* Overridden dimensions... */
	ATF_CHECK(!policy->allow_connect);
	ATF_CHECK(!policy->allow_udp);
	/* ...and the rest inherited from default. */
	ATF_CHECK(policy->resolve);
	ATF_CHECK(policy->ipv4);
	ATF_CHECK(policy->ipv6);
	ATF_CHECK(!policy->allow_internal);
	ATF_CHECK_EQ(16, policy->max_results);
	/* A per-label internal grant widens only that label. */
	policy = networkcmp_config_lookup(&config, "org.test.metrics", &listed);
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(listed);
	ATF_CHECK(policy->allow_internal);
	ATF_CHECK(policy->allow_connect);
}

/*
 * A label with no clients{} entry receives exactly the configured default.
 */
ATF_TC_WITHOUT_HEAD(unlisted_label_receives_default);
ATF_TC_BODY(unlisted_label_receives_default, tc)
{
	struct networkcmp_config config;
	const struct networkcmp_policy *policy;
	bool listed;

	ATF_REQUIRE_EQ(0, networkcmp_config_parse(
	    "default { udp = false; }\n"
	    "clients { \"org.test.render\" { connect = false; } }\n",
	    &config));
	policy = networkcmp_config_lookup(&config, "org.test.other", &listed);
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(!listed);
	ATF_CHECK(policy->allow_connect);
	ATF_CHECK(!policy->allow_udp);	/* narrowed default applies */
	ATF_CHECK(policy->resolve);
}

/*
 * A label whose entry turns every dimension off derives a policy that permits
 * nothing — networkcmp_policy_permits_any() is false, so the provider refuses
 * the session with EACCES (default-deny is expressible per label).
 */
ATF_TC_WITHOUT_HEAD(all_false_entry_permits_nothing);
ATF_TC_BODY(all_false_entry_permits_nothing, tc)
{
	struct networkcmp_config config;
	const struct networkcmp_policy *policy;
	bool listed;

	ATF_REQUIRE_EQ(0, networkcmp_config_parse(
	    "clients { \"org.test.denied\" { resolve = false;\n"
	    "  connect = false; udp = false; } }\n", &config));
	policy = networkcmp_config_lookup(&config, "org.test.denied", &listed);
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(listed);
	ATF_CHECK(!networkcmp_policy_permits_any(policy));
	ATF_CHECK_EQ(0, policy->max_results);
}

/*
 * The session-policy resolution order: ADMIN bypasses the table entirely and
 * receives the full policy including internal reach; a listed non-admin label
 * receives its entry; an unlisted one receives the default.  The reported
 * source strings back the session-start log line.
 */
ATF_TC_WITHOUT_HEAD(session_policy_resolution_order);
ATF_TC_BODY(session_policy_resolution_order, tc)
{
	struct networkcmp_config config;
	struct networkcmp_policy policy;
	const char *source;

	ATF_REQUIRE_EQ(0, networkcmp_config_parse(
	    "clients { \"org.test.render\" { connect = false; } }\n",
	    &config));
	/* ADMIN: full policy, internal included, table not consulted. */
	ATF_REQUIRE_EQ(0, networkcmp_config_session_policy(&config,
	    "org.test.render", SERVICE_RIGHTS_ADMIN, &policy, &source));
	ATF_CHECK_STREQ("admin", source);
	ATF_CHECK(policy.allow_connect);
	ATF_CHECK(policy.allow_internal);
	/* Listed label: its entry. */
	ATF_REQUIRE_EQ(0, networkcmp_config_session_policy(&config,
	    "org.test.render", SERVICE_RIGHTS_NONE, &policy, &source));
	ATF_CHECK_STREQ("label", source);
	ATF_CHECK(!policy.allow_connect);
	ATF_CHECK(policy.resolve);
	/* Unlisted label: the default. */
	ATF_REQUIRE_EQ(0, networkcmp_config_session_policy(&config,
	    "org.test.other", SERVICE_RIGHTS_NONE, &policy, &source));
	ATF_CHECK_STREQ("default", source);
	ATF_CHECK(policy.allow_connect);
	ATF_CHECK(!policy.allow_internal);
}

/*
 * Closed entry schema: an unknown key or a non-boolean value inside default{}
 * or a clients{} entry rejects the whole text and clears all normal grants.
 */
ATF_TC_WITHOUT_HEAD(unknown_or_mistyped_key_rejects_config);
ATF_TC_BODY(unknown_or_mistyped_key_rejects_config, tc)
{
	struct networkcmp_config config;

	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse(
	    "clients { \"org.test.render\" { conect = false; } }\n",
	    &config) == -1);
	ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));
	ATF_CHECK_EQ(0, (int)config.nclients);

	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse(
	    "default { connect = 3; }\n", &config) == -1);
	ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));

	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse(
	    "defaults { connect = true; }\n", &config) == -1);
	ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));
}

/*
 * Invalid or duplicate labels and non-object entries are malformed.
 */
ATF_TC_WITHOUT_HEAD(bad_labels_reject_config);
ATF_TC_BODY(bad_labels_reject_config, tc)
{
	struct networkcmp_config config;

	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse(
	    "clients { \"org.a\" { connect = false; }\n"
	    "  \"org.a\" { udp = false; } }\n", &config) == -1);
	ATF_CHECK_EQ(0, (int)config.nclients);
	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse(
	    "clients { \"bad label\" { connect = false; } }\n",
	    &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse(
	    "clients { \"org.a\" = true; }\n", &config) == -1);
}

/*
 * A malformed file must not replace configured restrictions with the compiled
 * outbound grant. Production startup treats the returned error as fatal.
 */
ATF_TC_WITHOUT_HEAD(malformed_file_revokes_grants);
ATF_TC_BODY(malformed_file_revokes_grants, tc)
{
	struct networkcmp_config config;
	const char *path;

	path = write_conf("clients { \"org.broken");
	ATF_CHECK(networkcmp_config_load(&config, path) == -1);
	ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));
	ATF_CHECK_EQ(0, (int)config.nclients);
	(void)unlink(path);

	/* A non-object root must not restore outbound grants. */
	path = write_conf("[ 1, 2, 3 ]");
	ATF_CHECK(networkcmp_config_load(&config, path) == -1);
	ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));
	(void)unlink(path);
}

/*
 * A MISSING file is the shipped-defaults case, not an error: load succeeds
 * and the compiled-in default policy stands.
 */
ATF_TC_WITHOUT_HEAD(missing_file_uses_defaults);
ATF_TC_BODY(missing_file_uses_defaults, tc)
{
	struct networkcmp_config config;

	ATF_CHECK_EQ(0, networkcmp_config_load(&config,
	    "./does-not-exist.conf"));
	check_shipped_default(&config.default_policy);
	ATF_CHECK_EQ(0, (int)config.nclients);
}

/*
 * A group/other-writable config is untrusted and must not restore grants.
 */
ATF_TC_WITHOUT_HEAD(writable_file_rejected_revokes_grants);
ATF_TC_BODY(writable_file_rejected_revokes_grants, tc)
{
	struct networkcmp_config config;
	const char *path;

	path = write_conf("clients { \"org.a\" { connect = false; } }\n");
	ATF_REQUIRE_EQ(0, chmod(path, 0666));
	ATF_CHECK_ERRNO(EPERM,
	    networkcmp_config_load(&config, path) == -1);
	ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));
	ATF_CHECK_EQ(0, (int)config.nclients);
	(void)unlink(path);
}

/*
 * A well-formed file loads: the default narrows and the entries land.
 */
ATF_TC_WITHOUT_HEAD(wellformed_file_loads);
ATF_TC_BODY(wellformed_file_loads, tc)
{
	struct networkcmp_config config;
	const struct networkcmp_policy *policy;
	const char *path;
	bool listed;

	path = write_conf("default { internal = false; udp = false; }\n"
	    "clients { \"org.test.render\" { connect = false; } }\n");
	ATF_CHECK_EQ(0, networkcmp_config_load(&config, path));
	ATF_CHECK_EQ(1, (int)config.nclients);
	policy = networkcmp_config_lookup(&config, "org.test.render", &listed);
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(listed);
	ATF_CHECK(!policy->allow_connect);
	ATF_CHECK(!policy->allow_udp);	/* inherited from narrowed default */
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct networkcmp_config config;

	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse(NULL, &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_parse("{}", NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_load(NULL, "x") == -1);
	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_load(&config, NULL) == -1);
	ATF_CHECK(networkcmp_config_lookup(NULL, "org.a", NULL) == NULL);
	ATF_CHECK_ERRNO(EINVAL, networkcmp_config_session_policy(NULL,
	    "org.a", SERVICE_RIGHTS_NONE, NULL, NULL) == -1);
}


ATF_TC_WITHOUT_HEAD(strict_policy_inputs);
ATF_TC_BODY(strict_policy_inputs, tc)
{
	struct networkcmp_config config;
	const char *bad[] = {
	    "\"default\\u0000suffix\" { internal = true; };",
	    "default { \"internal\\u0000suffix\" = true; };",
	    "clients { \"org.test\\u0000suffix\" { internal = true; }; };",
	    "default { connect = false; }; unknown = true;",
	};
	FILE *file;

	(void)tc;
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		ATF_CHECK_MSG(networkcmp_config_parse(bad[i], &config) == -1,
		    "accepted malformed input: %s", bad[i]);
		ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));
		ATF_CHECK_EQ(0, config.nclients);
	}
	file = fopen("external.ucl", "w");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fputs("default { internal = true; };", file) >= 0);
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_CHECK_EQ(-1, networkcmp_config_parse(".include \"external.ucl\"\n", &config));
	ATF_CHECK(!networkcmp_policy_permits_any(&config.default_policy));
	ATF_REQUIRE_EQ(0, unlink("external.ucl"));
}


ATF_TC_WITHOUT_HEAD(confined_descriptor_policy);
ATF_TC_BODY(confined_descriptor_policy, tc)
{
	struct networkcmp_config config;
	const char text[] = "default { internal = true; };";
	char path[] = "confined-policy.XXXXXX";
	cap_rights_t rights;
	int fd;

	(void)tc;
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, unlink(path));
	ATF_REQUIRE_EQ((ssize_t)(sizeof(text) - 1), write(fd, text, sizeof(text) - 1));
	cap_rights_init(&rights, CAP_PREAD, CAP_FSTAT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, cap_enter());
	/* The descriptor is at EOF and has no ordinary namespace authority. */
	ATF_REQUIRE_EQ(0, networkcmp_config_load_fd(&config, fd));
	ATF_REQUIRE(config.default_policy.allow_internal);
	ATF_REQUIRE_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
}

ATF_TC_WITHOUT_HEAD(shipped_policy);
ATF_TC_BODY(shipped_policy, tc)
{
	struct networkcmp_config config;
	char path[4096];

	snprintf(path, sizeof(path),
	    "%s/srctree/usr.sbin/BSDNetwork/capbundle/bsdnetwork.conf",
	    atf_tc_get_config_var(tc, "srcdir"));
	ATF_REQUIRE_EQ(0, access(path, R_OK));
	ATF_REQUIRE_EQ(0, networkcmp_config_load(&config, path));
	check_shipped_default(&config.default_policy);
	ATF_CHECK(!config.default_policy.allow_listen);
	ATF_CHECK_EQ(0, config.nclients);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, shipped_policy);
	ATF_TP_ADD_TC(tp, confined_descriptor_policy);
	ATF_TP_ADD_TC(tp, strict_policy_inputs);

	ATF_TP_ADD_TC(tp, compiled_default_matches_historical_grant);
	ATF_TP_ADD_TC(tp, client_entry_overrides_and_inherits);
	ATF_TP_ADD_TC(tp, unlisted_label_receives_default);
	ATF_TP_ADD_TC(tp, all_false_entry_permits_nothing);
	ATF_TP_ADD_TC(tp, session_policy_resolution_order);
	ATF_TP_ADD_TC(tp, unknown_or_mistyped_key_rejects_config);
	ATF_TP_ADD_TC(tp, bad_labels_reject_config);
	ATF_TP_ADD_TC(tp, malformed_file_revokes_grants);
	ATF_TP_ADD_TC(tp, missing_file_uses_defaults);
	ATF_TP_ADD_TC(tp, writable_file_rejected_revokes_grants);
	ATF_TP_ADD_TC(tp, wellformed_file_loads);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
