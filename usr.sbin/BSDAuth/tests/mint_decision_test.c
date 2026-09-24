/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The SYSTEM-vs-USER mint decision, unit-tested through the pure predicate
 * authagent_mint_kind() the daemon factored out of handle_request().  Since
 * IPC anointments v1 the decision is grant-based, and VISIBILITY is decoupled
 * from management: a principal whose grant holds "*" (see-everything) mints a
 * full-discovery SYSTEM channel; every other principal -- including an operator
 * carrying admin_rights but not "*" -- mints a per-uid USER channel that carries
 * its anointment set.  This mirrors lib/libcapbundle's principal-policy tests
 * (temp policy files) one layer up — at the daemon's own decision point —
 * rather than duplicating the policy engine's own coverage.
 *
 * Pure: no plane, no switchboard, no Casper.  Runs anywhere.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <libcapbundle.h>

#include "bsdauth_test.h"

/*
 * A group-name resolver that knows nothing.  The uid-keyed policies below name
 * no groups, so this is never consulted; it stands in for the daemon's
 * in-process group database and proves the decision core needs no group
 * database of its own for these cases.
 */
static gid_t
no_groups(void *ctx __unused, const char *name __unused)
{

	return ((gid_t)-1);
}

/* wheel == 0, operators == 500. */
static gid_t
default_groups(void *ctx __unused, const char *name)
{

	if (strcmp(name, "wheel") == 0)
		return (0);
	if (strcmp(name, "operators") == 0)
		return (500);
	return ((gid_t)-1);
}

/* Write `text` to a fresh temp file; caller unlinks via the returned path. */
static void
write_policy(char path[], size_t pathlen, const char *text)
{
	FILE *fp;
	int fd;

	strlcpy(path, "/tmp/authagent_policy.XXXXXX", pathlen);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	fp = fdopen(fd, "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

static int
open_policy(char path[], size_t pathlen, const char *text)
{
	int fd;

	write_policy(path, pathlen, text);
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

#define	NEW_FORMAT_POLICY \
	"principals {\n" \
	"  admin { groups = [\"wheel\"]; uids = [0]; anointments = [\"*\"];" \
	" admin_rights = true; }\n" \
	"  default { anointments = []; }\n" \
	"  operators { groups = [\"operators\"];" \
	" anointments = [\"system.trace.client\", \"a.two\"];" \
	" may_elevate = [\"system.notify.system\"]; }\n" \
	"}\n"

/*
 * With no policy delivered (fd == -1) the fail-closed least-privilege default
 * applies: uid 0 is not magic, holds no "*", and mints a narrowed USER channel.
 */
ATF_TC_WITHOUT_HEAD(default_root_mints_user);
ATF_TC_BODY(default_root_mints_user, tc)
{

	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(-1, 0, NULL, 0, no_groups, NULL));
}

/*
 * A non-admin principal (a synthetic uid in no group) mints USER under the
 * default policy.
 */
ATF_TC_WITHOUT_HEAD(default_nonadmin_mints_user);
ATF_TC_BODY(default_nonadmin_mints_user, tc)
{
	gid_t members[] = { 1234 };

	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(-1, 1234, members, 1, no_groups, NULL));
}

/* Legacy admin { uids } policy: SYSTEM for it and USER for everyone else. */
ATF_TC_WITHOUT_HEAD(legacy_policy_admin_uid_mints_system);
ATF_TC_BODY(legacy_policy_admin_uid_mints_system, tc)
{
	gid_t granted_groups[] = { 1234 };
	gid_t other_groups[] = { 5678 };
	char path[64];
	int fd;

	fd = open_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM,
	    authagent_mint_kind(fd, 1234, granted_groups, 1, no_groups, NULL));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 5678, other_groups, 1, no_groups, NULL));
	(void)close(fd);
	(void)unlink(path);
}

/*
 * An authoritative legacy policy that names no uids denies even root: root
 * is not automatically privileged in the capability model, so it mints USER.
 */
ATF_TC_WITHOUT_HEAD(legacy_policy_without_root_mints_user_for_root);
ATF_TC_BODY(legacy_policy_without_root_mints_user_for_root, tc)
{
	char path[64];
	int fd;

	fd = open_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 0, NULL, 0, no_groups, NULL));
	(void)close(fd);
	(void)unlink(path);
}

/* New format: admin -> SYSTEM, default -> USER, operators -> USER. */
ATF_TC_WITHOUT_HEAD(new_format_kinds);
ATF_TC_BODY(new_format_kinds, tc)
{
	const gid_t wheel_member[] = { 1234, 0 };
	const gid_t operator_member[] = { 1235, 500 };
	const gid_t ordinary_member[] = { 1236 };
	char path[64];
	int fd;

	fd = open_policy(path, sizeof(path), NEW_FORMAT_POLICY);
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM,
	    authagent_mint_kind(fd, 0, NULL, 0, default_groups, NULL));
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM,
	    authagent_mint_kind(fd, 1234, wheel_member, 2, default_groups,
	    NULL));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 1235, operator_member, 2, default_groups,
	    NULL));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 1236, ordinary_member, 1, default_groups,
	    NULL));
	(void)close(fd);
	(void)unlink(path);
}

/*
 * The anointed set the mint carries is the grant's set, passed through
 * unchanged: an operator session holds exactly what its entry lists, and
 * nothing it may only elevate to.
 */
ATF_TC_WITHOUT_HEAD(new_format_set_passed_through);
ATF_TC_BODY(new_format_set_passed_through, tc)
{
	struct capbundle_principal_grant g;
	const gid_t operator_member[] = { 1235, 500 };
	const gid_t ordinary_member[] = { 1236 };
	char path[64];
	int fd;

	fd = open_policy(path, sizeof(path), NEW_FORMAT_POLICY);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 1235,
	    operator_member, 2, default_groups, NULL, &g));
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(!g.admin_rights);
	ATF_REQUIRE_EQ(2U, g.nanointments);
	ATF_CHECK_STREQ("system.trace.client", g.anointments[0]);
	ATF_CHECK_STREQ("a.two", g.anointments[1]);
	ATF_CHECK(capbundle_principal_holds(&g, "system.trace.client"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system.notify.system"));
	ATF_CHECK(!g.from_default_rule);

	/* The default entry: an empty set on a USER channel. */
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 1236,
	    ordinary_member, 1, default_groups, NULL, &g));
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	ATF_CHECK_EQ(0U, g.nanointments);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(!g.admin_rights);
	ATF_CHECK_EQ(0U, g.nmay_elevate);
	ATF_CHECK(!g.elevate_all);

	/* Admin: "*" with admin rights, no list. */
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    default_groups, NULL, &g));
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM, authagent_mint_kind_for_grant(&g));
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(g.admin_rights);
	ATF_CHECK_EQ(0U, g.nanointments);
	(void)close(fd);
	(void)unlink(path);
}

/*
 * Visibility is driven ONLY by "*" (see-everything): "*" -> SYSTEM regardless
 * of admin_rights; admin_rights without "*" is management authority only and
 * stays USER; neither -> USER.  This is the manage/see decoupling.
 */
ATF_TC_WITHOUT_HEAD(kind_only_from_see_all);
ATF_TC_BODY(kind_only_from_see_all, tc)
{
	struct capbundle_principal_grant g;

	/*
	 * VISIBILITY is decoupled from management: ONLY "*" (anoint_all,
	 * see-everything) mints SYSTEM.  admin_rights is the operator/management
	 * bit and must NOT, on its own, grant full discovery -- an operator
	 * without "*" manages from a narrowed USER channel.
	 */
	memset(&g, 0, sizeof(g));
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	g.anoint_all = true;
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM, authagent_mint_kind_for_grant(&g));
	/* admin_rights alone (no "*") is management authority, NOT visibility. */
	g.anoint_all = false;
	g.admin_rights = true;
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	/* A specific (non-"*") anointment set stays USER too. */
	g.nanointments = 3;
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
}

/*
 * P6: root with some anointments, may_elevate "*", admin_rights = false is
 * a USER-kind session -- root has some, not all.
 */
ATF_TC_WITHOUT_HEAD(p6_root_some_not_all);
ATF_TC_BODY(p6_root_some_not_all, tc)
{
	struct capbundle_principal_grant g;
	char path[64];
	int fd;

	fd = open_policy(path, sizeof(path),
	    "principals {\n"
	    "  root { uids = [0]; anointments = [\"system.switchboard.admin\"];"
	    " may_elevate = [\"*\"]; admin_rights = false; }\n"
	    "  default { anointments = []; }\n"
	    "}\n");
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    default_groups, NULL, &g));
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 0, NULL, 0, default_groups, NULL));
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK(g.elevate_all);
	ATF_CHECK(!g.admin_rights);
	(void)close(fd);
	(void)unlink(path);
}

/* P9: the strict-admin profile mints USER: nothing held until anointed. */
ATF_TC_WITHOUT_HEAD(p9_strict_admin_mints_user);
ATF_TC_BODY(p9_strict_admin_mints_user, tc)
{
	struct capbundle_principal_grant g;
	const gid_t wheel_member[] = { 1234, 0 };
	char path[64];
	int fd;

	fd = open_policy(path, sizeof(path),
	    "principals {\n"
	    "  admin { groups = [\"wheel\"]; anointments = [];"
	    " may_elevate = [\"*\"]; }\n"
	    "  default { anointments = []; }\n"
	    "}\n");
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 1234, wheel_member,
	    2, default_groups, NULL, &g));
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	ATF_CHECK_EQ(0U, g.nanointments);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(g.elevate_all);
	(void)close(fd);
	(void)unlink(path);
}

/* P10: a malformed policy falls back to the least-privilege default (flagged):
 * fail-closed, so even uid 0 / wheel mint USER, not SYSTEM. */
ATF_TC_WITHOUT_HEAD(p10_malformed_policy_falls_back);
ATF_TC_BODY(p10_malformed_policy_falls_back, tc)
{
	struct capbundle_principal_grant g;
	const gid_t wheel_member[] = { 1234, 0 };
	const gid_t ordinary_member[] = { 1236 };
	char path[64];
	int fd;

	fd = open_policy(path, sizeof(path),
	    "principals { admin { anointments = [\"not a name\"] } \n");
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 0, NULL, 0, default_groups, NULL));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 1234, wheel_member, 2, default_groups,
	    NULL));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 1236, ordinary_member, 1, default_groups,
	    NULL));
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 1236,
	    ordinary_member, 1, default_groups, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	(void)close(fd);
	(void)unlink(path);
}

/*
 * The policy shipped in bsdauth (new format) reproduces the documented
 * root/wheel rule: admin holds "*" with admin rights, default holds nothing
 * and may elevate nothing.
 */
ATF_TC_WITHOUT_HEAD(packaged_default_matches_root_and_wheel);
ATF_TC_BODY(packaged_default_matches_root_and_wheel, tc)
{
	struct capbundle_principal_grant g;
	const gid_t wheel_member[] = { 0 };
	const gid_t ordinary_member[] = { 1235 };
	int fd;

	/* The source copy on a build host, else the installed file, else skip. */
	fd = open(DEFAULT_POLICY_PATH, O_RDONLY);
	if (fd < 0)
		fd = open("/Capabilities/Config/principal-policy.ucl", O_RDONLY);
	if (fd < 0)
		atf_tc_skip("shipped principal-policy.ucl not available here");
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM,
	    authagent_mint_kind(fd, 0, NULL, 0, default_groups, NULL));
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM,
	    authagent_mint_kind(fd, 1234, wheel_member, 1, default_groups, NULL));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 1235, ordinary_member, 1, default_groups,
	    NULL));

	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    default_groups, NULL, &g));
	ATF_CHECK(!g.from_default_rule);	/* the file parsed */
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(g.admin_rights);
	ATF_CHECK(!g.elevate_all);
	ATF_CHECK_EQ(0U, g.nmay_elevate);

	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 1235,
	    ordinary_member, 1, default_groups, NULL, &g));
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(!g.admin_rights);
	ATF_CHECK_EQ(0U, g.nanointments);
	ATF_CHECK(!g.elevate_all);
	ATF_CHECK_EQ(0U, g.nmay_elevate);
	(void)close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, default_root_mints_user);
	ATF_TP_ADD_TC(tp, default_nonadmin_mints_user);
	ATF_TP_ADD_TC(tp, legacy_policy_admin_uid_mints_system);
	ATF_TP_ADD_TC(tp, legacy_policy_without_root_mints_user_for_root);
	ATF_TP_ADD_TC(tp, new_format_kinds);
	ATF_TP_ADD_TC(tp, new_format_set_passed_through);
	ATF_TP_ADD_TC(tp, kind_only_from_see_all);
	ATF_TP_ADD_TC(tp, p6_root_some_not_all);
	ATF_TP_ADD_TC(tp, p9_strict_admin_mints_user);
	ATF_TP_ADD_TC(tp, p10_malformed_policy_falls_back);
	ATF_TP_ADD_TC(tp, packaged_default_matches_root_and_wheel);
	return (atf_no_error());
}
