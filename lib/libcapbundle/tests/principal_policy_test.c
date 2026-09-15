/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the principal policy (docs/capability-authority-model.md,
 * P1; docs/ipc-anointments-design.md, "Domains and sessions").  The
 * path-parameterized core capbundle_principal_is_admin_at() and the grant
 * resolver capbundle_principal_resolve() are driven with temporary policy
 * files and a synthetic group resolver -- no host group database is consulted.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libcapbundle_internal.h"

/* A synthetic principal, not present in any group database on the host. */
static struct passwd
principal(uid_t uid)
{
	struct passwd pw;

	memset(&pw, 0, sizeof(pw));
	pw.pw_name = __DECONST(char *, "cap_policy_test_user");
	pw.pw_uid = uid;
	pw.pw_gid = uid;
	return (pw);
}

/* Write `text` to a fresh temp file; caller unlinks via the returned path. */
static void
write_policy(char path[], size_t pathlen, const char *text)
{
	int fd;
	FILE *fp;

	strlcpy(path, "/tmp/cappolicy.XXXXXX", pathlen);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	fp = fdopen(fd, "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

ATF_TC_WITHOUT_HEAD(no_policy_defaults_to_root);
ATF_TC_BODY(no_policy_defaults_to_root, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);

	/* Absent policy: historical default -- root is admin, others are not
	 * (the synthetic user is in no group, so not in wheel). */
	ATF_CHECK(capbundle_principal_is_admin_at(&root,
	    "/nonexistent/principal-policy.ucl"));
	ATF_CHECK(!capbundle_principal_is_admin_at(&user,
	    "/nonexistent/principal-policy.ucl"));
}

ATF_TC_WITHOUT_HEAD(policy_grants_by_uid);
ATF_TC_BODY(policy_grants_by_uid, tc)
{
	struct passwd granted = principal(1234);
	struct passwd other = principal(5678);
	char path[64];

	write_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	ATF_CHECK(capbundle_principal_is_admin_at(&granted, path));
	ATF_CHECK(!capbundle_principal_is_admin_at(&other, path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(valid_policy_is_authoritative);
ATF_TC_BODY(valid_policy_is_authoritative, tc)
{
	struct passwd root = principal(0);
	char path[64];

	/* A valid policy that lists no uids is authoritative: even root is not
	 * an administrator unless the policy names it.  (This is the model --
	 * root is not automatically privileged.) */
	write_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	ATF_CHECK(!capbundle_principal_is_admin_at(&root, path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(malformed_policy_fails_safe_to_default);
ATF_TC_BODY(malformed_policy_fails_safe_to_default, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);
	char path[64];

	/* An unparseable policy must fall back to the historical default so a
	 * typo can never lock root out. */
	write_policy(path, sizeof(path), "admin { uids = [ this is not ucl \n");
	ATF_CHECK(capbundle_principal_is_admin_at(&root, path));
	ATF_CHECK(!capbundle_principal_is_admin_at(&user, path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(null_principal_is_not_admin);
ATF_TC_BODY(null_principal_is_not_admin, tc)
{

	ATF_CHECK(!capbundle_principal_is_admin_at(NULL,
	    "/nonexistent/principal-policy.ucl"));
}

/* The fd form: same decisions, reading the policy from an open descriptor. */
ATF_TC_WITHOUT_HEAD(policy_fd_grants_by_uid);
ATF_TC_BODY(policy_fd_grants_by_uid, tc)
{
	struct passwd granted = principal(4242);
	struct passwd other = principal(4243);
	char path[64];
	int fd;

	write_policy(path, sizeof(path), "admin { uids = [ 4242 ] }\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(capbundle_principal_is_admin_fd(&granted, fd));
	ATF_CHECK(!capbundle_principal_is_admin_fd(&other, fd));
	(void)close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(policy_fd_absent_defaults_to_root);
ATF_TC_BODY(policy_fd_absent_defaults_to_root, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);

	/* -1 fd (policy not delivered): historical default applies. */
	ATF_CHECK(capbundle_principal_is_admin_fd(&root, -1));
	ATF_CHECK(!capbundle_principal_is_admin_fd(&user, -1));
}


/* ---- grant resolution (IPC anointments) ----------------------------- */

#define	GID_WHEEL	0
#define	GID_OPERATORS	100
#define	GID_STAFF	20

/* A synthetic group database: only these three names resolve. */
static gid_t
stub_name2gid(void *ctx, const char *name)
{
	int *calls = ctx;

	if (calls != NULL)
		(*calls)++;
	if (strcmp(name, "wheel") == 0)
		return (GID_WHEEL);
	if (strcmp(name, "operators") == 0)
		return (GID_OPERATORS);
	if (strcmp(name, "staff") == 0)
		return (GID_STAFF);
	return ((gid_t)-1);
}

/*
 * Resolve `uid` (member of `gids`) against policy `text` written to a temp
 * file.  text == NULL means no file (fd -1).
 */
static void
resolve(const char *text, uid_t uid, const gid_t *gids, unsigned ngids,
    struct capbundle_principal_grant *g)
{
	char path[64];
	int fd = -1;

	memset(g, 0xa5, sizeof(*g));
	if (text != NULL) {
		write_policy(path, sizeof(path), text);
		fd = open(path, O_RDONLY);
		ATF_REQUIRE(fd >= 0);
		(void)unlink(path);
	}
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, uid, gids, ngids,
	    stub_name2gid, NULL, g));
	if (fd >= 0)
		(void)close(fd);
}

static const char shipped_policy[] =
    "principals {\n"
    "    admin     { groups = [\"wheel\"]; uids = [0]; anointments = [\"*\"];"
    " admin_rights = true; }\n"
    "    default   { anointments = []; }\n"
    "    operators { groups = [\"operators\"];"
    " anointments = [\"system.trace.client\"];"
    " may_elevate = [\"system.notify.system\"]; }\n"
    "}\n";

static void
check_empty_grant(const struct capbundle_principal_grant *g)
{

	ATF_CHECK_EQ(0U, g->nanointments);
	ATF_CHECK(!g->anoint_all);
	ATF_CHECK_EQ(0U, g->nmay_elevate);
	ATF_CHECK(!g->elevate_all);
	ATF_CHECK(!g->admin_rights);
	ATF_CHECK(!capbundle_principal_holds(g, "system.notify.system"));
	ATF_CHECK(!capbundle_principal_may_elevate(g, "system.notify.system"));
}

static void
check_full_admin_grant(const struct capbundle_principal_grant *g)
{

	ATF_CHECK(g->anoint_all);
	ATF_CHECK(g->admin_rights);
	ATF_CHECK_EQ(0U, g->nanointments);
	ATF_CHECK(!g->elevate_all);
	ATF_CHECK_EQ(0U, g->nmay_elevate);
	ATF_CHECK(capbundle_principal_holds(g, "system.notify.system"));
	ATF_CHECK(capbundle_principal_holds(g, "anything.at.all"));
	ATF_CHECK(!capbundle_principal_may_elevate(g, "system.notify.system"));
}

ATF_TC_WITHOUT_HEAD(grant_admin_by_uid);
ATF_TC_BODY(grant_admin_by_uid, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { GID_STAFF };

	/* uid 0 in no admin group still matches the uids selector. */
	resolve(shipped_policy, 0, gids, 1, &g);
	check_full_admin_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(grant_admin_by_group);
ATF_TC_BODY(grant_admin_by_group, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { GID_STAFF, GID_WHEEL };

	resolve(shipped_policy, 1001, gids, 2, &g);
	check_full_admin_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(grant_default_user_is_empty);
ATF_TC_BODY(grant_default_user_is_empty, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { GID_STAFF };

	resolve(shipped_policy, 1001, gids, 1, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	/* No groups at all: still the default entry. */
	resolve(shipped_policy, 1001, NULL, 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(grant_operators_by_group);
ATF_TC_BODY(grant_operators_by_group, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { GID_STAFF, GID_OPERATORS };

	resolve(shipped_policy, 1002, gids, 2, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("system.trace.client", g.anointments[0]);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK_EQ(1U, g.nmay_elevate);
	ATF_CHECK_STREQ("system.notify.system", g.may_elevate[0]);
	ATF_CHECK(!g.elevate_all);
	ATF_CHECK(!g.admin_rights);
	/* P1/P2: holds trace, not notify. */
	ATF_CHECK(capbundle_principal_holds(&g, "system.trace.client"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system.notify.system"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system.storage.admin"));
	/* P3/P5: may elevate to notify, not storage. */
	ATF_CHECK(capbundle_principal_may_elevate(&g, "system.notify.system"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "system.storage.admin"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "system.trace.client"));
}

ATF_TC_WITHOUT_HEAD(grant_first_match_wins);
ATF_TC_BODY(grant_first_match_wins, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { GID_OPERATORS, GID_WHEEL };

	/* Both entries match; file order decides. */
	resolve("principals {\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "  adm { groups = [\"wheel\"]; anointments = [\"*\"]; }\n"
	    "}\n", 7, gids, 2, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.ops", g.anointments[0]);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(!g.admin_rights);

	resolve("principals {\n"
	    "  adm { groups = [\"wheel\"]; anointments = [\"*\"]; }\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "}\n", 7, gids, 2, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(g.admin_rights);
	ATF_CHECK_EQ(0U, g.nanointments);

	/* uid match in a later entry loses to a group match in an earlier one. */
	resolve("principals {\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "  me  { uids = [7]; anointments = [\"a.me\"]; }\n"
	    "}\n", 7, gids, 2, &g);
	ATF_CHECK_STREQ("a.ops", g.anointments[0]);
}

ATF_TC_WITHOUT_HEAD(grant_default_fallback_regardless_of_position);
ATF_TC_BODY(grant_default_fallback_regardless_of_position, tc)
{
	struct capbundle_principal_grant g;
	gid_t ops[] = { GID_OPERATORS };
	gid_t none[] = { GID_STAFF };

	/* The default entry comes first; a later matching entry still wins. */
	resolve("principals {\n"
	    "  default { anointments = [\"a.default\"]; }\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "}\n", 7, ops, 1, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.ops", g.anointments[0]);

	resolve("principals {\n"
	    "  default { anointments = [\"a.default\"]; }\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "}\n", 7, none, 1, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.default", g.anointments[0]);
	ATF_CHECK(!g.from_default_rule);

	/* Any entry with neither uids nor groups is a fallback, whatever its
	 * name; the first such entry applies. */
	resolve("principals {\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "  everyone { anointments = [\"a.everyone\"]; }\n"
	    "  later { anointments = [\"a.later\"]; }\n"
	    "}\n", 7, none, 1, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.everyone", g.anointments[0]);
}

ATF_TC_WITHOUT_HEAD(grant_no_match_no_default_is_empty);
ATF_TC_BODY(grant_no_match_no_default_is_empty, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { GID_STAFF };

	resolve("principals {\n"
	    "  adm { groups = [\"wheel\"]; anointments = [\"*\"]; }\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "}\n", 7, gids, 1, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	/* Root with a valid policy that never names it: nothing.  The policy
	 * is authoritative. */
	resolve("principals {\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "}\n", 0, NULL, 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	/* An empty principals block: everyone gets nothing. */
	resolve("principals { }\n", 0, NULL, 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(grant_star_sets_all_flags);
ATF_TC_BODY(grant_star_sets_all_flags, tc)
{
	struct capbundle_principal_grant g;

	/* P6: some anointments, elevate anything, no ADMIN bit. */
	resolve("principals {\n"
	    "  root { uids = [0]; anointments = [\"system.switchboard.admin\"];"
	    " may_elevate = [\"*\"]; admin_rights = false; }\n"
	    "}\n", 0, NULL, 0, &g);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK(g.elevate_all);
	ATF_CHECK_EQ(0U, g.nmay_elevate);
	ATF_CHECK(!g.admin_rights);
	ATF_CHECK(capbundle_principal_holds(&g, "system.switchboard.admin"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system.storage.admin"));
	ATF_CHECK(capbundle_principal_may_elevate(&g, "system.storage.admin"));
	ATF_CHECK(capbundle_principal_may_elevate(&g, "x.y"));

	/* "*" mixed with names: the flag is set, the names still recorded. */
	resolve("principals {\n"
	    "  root { uids = [0]; anointments = [\"a.b\", \"*\", \"c.d\"]; }\n"
	    "}\n", 0, NULL, 0, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK_EQ(2U, g.nanointments);
	ATF_CHECK(g.admin_rights);

	/* Scalar-string form of "*". */
	resolve("principals { root { uids = [0]; anointments = \"*\"; } }\n",
	    0, NULL, 0, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(g.admin_rights);
}

ATF_TC_WITHOUT_HEAD(grant_admin_rights_defaults);
ATF_TC_BODY(grant_admin_rights_defaults, tc)
{
	struct capbundle_principal_grant g;

	/* Absent with "*": true. */
	resolve("principals { r { uids = [0]; anointments = [\"*\"]; } }\n",
	    0, NULL, 0, &g);
	ATF_CHECK(g.admin_rights);
	/* Explicit false with "*": honoured. */
	resolve("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = false; } }\n", 0, NULL, 0, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(!g.admin_rights);
	/* Absent without "*": false. */
	resolve("principals { r { uids = [0]; anointments = [\"a.b\"]; } }\n",
	    0, NULL, 0, &g);
	ATF_CHECK(!g.admin_rights);
	/* Explicit true without any anointments: honoured (bypass without
	 * reach). */
	resolve("principals { r { uids = [0]; admin_rights = true; } }\n",
	    0, NULL, 0, &g);
	ATF_CHECK(g.admin_rights);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK_EQ(0U, g.nanointments);
	/* may_elevate = ["*"] alone does not imply admin_rights (P9). */
	resolve("principals { r { uids = [0]; anointments = [];"
	    " may_elevate = [\"*\"]; } }\n", 0, NULL, 0, &g);
	ATF_CHECK(!g.admin_rights);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(g.elevate_all);
	ATF_CHECK(!capbundle_principal_holds(&g, "a.b"));
}

ATF_TC_WITHOUT_HEAD(grant_selectors_forms);
ATF_TC_BODY(grant_selectors_forms, tc)
{
	struct capbundle_principal_grant g;
	gid_t ops[] = { GID_OPERATORS };

	/* Scalar uid and scalar group. */
	resolve("principals { r { uids = 7; anointments = [\"a.uid\"]; } }\n",
	    7, NULL, 0, &g);
	ATF_CHECK_STREQ("a.uid", g.anointments[0]);
	resolve("principals { r { groups = \"operators\";"
	    " anointments = [\"a.grp\"]; } }\n", 7, ops, 1, &g);
	ATF_CHECK_STREQ("a.grp", g.anointments[0]);
	/* Several uids / groups; an unknown group name never matches but is
	 * not an error. */
	resolve("principals { r { uids = [1, 2, 7]; groups = [\"nosuch\","
	    " \"staff\"]; anointments = [\"a.multi\"]; } }\n", 7, NULL, 0, &g);
	ATF_CHECK_STREQ("a.multi", g.anointments[0]);
	resolve("principals { r { uids = [1, 2]; groups = [\"nosuch\"];"
	    " anointments = [\"a.multi\"]; } }\n", 7, ops, 1, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	/* Duplicate names are folded, not an error. */
	resolve("principals { r { uids = [7]; anointments = [\"a.b\", \"a.b\"];"
	    " } }\n", 7, NULL, 0, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
}

ATF_TC_WITHOUT_HEAD(grant_legacy_admin_block);
ATF_TC_BODY(grant_legacy_admin_block, tc)
{
	struct capbundle_principal_grant g;
	gid_t wheel[] = { GID_WHEEL };
	gid_t staff[] = { GID_STAFF };

	resolve("admin { uids = [ 1234 ]; groups = [ \"wheel\" ]; }\n",
	    1234, NULL, 0, &g);
	check_full_admin_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	resolve("admin { uids = [ 1234 ]; groups = [ \"wheel\" ]; }\n",
	    5678, wheel, 1, &g);
	check_full_admin_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	resolve("admin { uids = [ 1234 ]; groups = [ \"wheel\" ]; }\n",
	    5678, staff, 1, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	/* Legacy and authoritative: root not listed gets nothing. */
	resolve("admin { uids = [ 1234 ] }\n", 0, NULL, 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	/* A valid file with neither block: nobody is anything. */
	resolve("# nothing here\nother = 1;\n", 0, NULL, 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(grant_missing_file_uses_historical_rule);
ATF_TC_BODY(grant_missing_file_uses_historical_rule, tc)
{
	struct capbundle_principal_grant g;
	gid_t wheel[] = { GID_STAFF, GID_WHEEL };
	gid_t staff[] = { GID_STAFF };

	resolve(NULL, 0, NULL, 0, &g);
	ATF_CHECK(g.from_default_rule);
	check_full_admin_grant(&g);

	resolve(NULL, 1001, wheel, 2, &g);
	ATF_CHECK(g.from_default_rule);
	check_full_admin_grant(&g);

	resolve(NULL, 1001, staff, 1, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);

	/* An empty file is "no policy" too. */
	resolve("", 0, NULL, 0, &g);
	ATF_CHECK(g.from_default_rule);
	check_full_admin_grant(&g);
}

ATF_TC_WITHOUT_HEAD(grant_malformed_file_uses_historical_rule);
ATF_TC_BODY(grant_malformed_file_uses_historical_rule, tc)
{
	struct capbundle_principal_grant g;
	gid_t staff[] = { GID_STAFF };

	resolve("principals { admin { uids = [ this is not ucl \n",
	    0, NULL, 0, &g);
	ATF_CHECK(g.from_default_rule);
	check_full_admin_grant(&g);

	resolve("principals { admin { uids = [ this is not ucl \n",
	    1001, staff, 1, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
}

/* Every schema violation is "malformed": the whole file falls back. */
static void
check_falls_back(const char *text)
{
	struct capbundle_principal_grant g;
	gid_t staff[] = { GID_STAFF };

	resolve(text, 0, NULL, 0, &g);
	ATF_CHECK_MSG(g.from_default_rule, "accepted: %s", text);
	ATF_CHECK(g.anoint_all && g.admin_rights);
	resolve(text, 1001, staff, 1, &g);
	ATF_CHECK_MSG(g.from_default_rule, "accepted: %s", text);
	check_empty_grant(&g);
}

ATF_TC_WITHOUT_HEAD(grant_unknown_key_in_entry_is_malformed);
ATF_TC_BODY(grant_unknown_key_in_entry_is_malformed, tc)
{

	check_falls_back("principals { r { uids = [0]; anointments = [\"*\"];"
	    " rights = true; } }\n");
	/* ... even in an entry after the one that would have matched. */
	check_falls_back("principals {\n"
	    "  r { uids = [0]; anointments = [\"*\"]; }\n"
	    "  ops { groups = [\"operators\"]; anoint = [\"a.b\"]; }\n"
	    "}\n");
	/* ... and in the default entry. */
	check_falls_back("principals {\n"
	    "  r { uids = [0]; anointments = [\"*\"]; }\n"
	    "  default { anointments = []; elevate = []; }\n"
	    "}\n");
	/* Legacy block is closed too. */
	check_falls_back("admin { uids = [0]; anointments = [\"*\"]; }\n");
}

ATF_TC_WITHOUT_HEAD(grant_bad_types_are_malformed);
ATF_TC_BODY(grant_bad_types_are_malformed, tc)
{

	check_falls_back("principals = 7;\n");
	check_falls_back("principals = [\"r\"];\n");
	check_falls_back("principals { r = 7; }\n");
	check_falls_back("principals { r { uids = \"0\"; } }\n");
	check_falls_back("principals { r { uids = [0, \"x\"]; } }\n");
	check_falls_back("principals { r { uids = [-1]; } }\n");
	check_falls_back("principals { r { groups = 7; } }\n");
	check_falls_back("principals { r { groups = [\"wheel\", 7]; } }\n");
	check_falls_back("principals { r { groups = [\"\"]; } }\n");
	check_falls_back("principals { r { uids = [0]; anointments = 7; } }\n");
	check_falls_back("principals { r { uids = [0]; anointments = [7]; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " anointments = { a = 1 }; } }\n");
	check_falls_back("principals { r { uids = [0]; may_elevate = true; } }\n");
	check_falls_back("principals { r { uids = [0]; admin_rights = 1; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " admin_rights = \"true\"; } }\n");
	check_falls_back("admin = 7;\n");
	check_falls_back("admin { uids = \"root\"; }\n");
}

ATF_TC_WITHOUT_HEAD(grant_invalid_names_are_malformed);
ATF_TC_BODY(grant_invalid_names_are_malformed, tc)
{
	char text[512];
	char name[80];

	check_falls_back("principals { r { uids = [0];"
	    " anointments = [\"nodot\"]; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " anointments = [\"\"]; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " anointments = [\"a..b\"]; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " may_elevate = [\"a.b!\"]; } }\n");
	/* "**" and "*.x" are not the wildcard. */
	check_falls_back("principals { r { uids = [0];"
	    " anointments = [\"**\"]; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " anointments = [\"*.x\"]; } }\n");
	/* Too long. */
	memset(name, 'b', sizeof(name));
	name[0] = 'a';
	name[1] = '.';
	name[CAPBUNDLE_LABEL_MAX] = '\0';
	snprintf(text, sizeof(text), "principals { r { uids = [0];"
	    " anointments = [\"%s\"]; } }\n", name);
	check_falls_back(text);
	/* Exactly the limit is fine. */
	{
		struct capbundle_principal_grant g;

		name[CAPBUNDLE_LABEL_MAX - 1] = '\0';
		snprintf(text, sizeof(text), "principals { r { uids = [0];"
		    " anointments = [\"%s\"]; } }\n", name);
		resolve(text, 0, NULL, 0, &g);
		ATF_CHECK(!g.from_default_rule);
		ATF_CHECK_EQ(1U, g.nanointments);
		ATF_CHECK(capbundle_principal_holds(&g, name));
	}
}

ATF_TC_WITHOUT_HEAD(grant_too_many_names_is_malformed);
ATF_TC_BODY(grant_too_many_names_is_malformed, tc)
{
	struct capbundle_principal_grant g;
	char text[4096];
	unsigned i;

	snprintf(text, sizeof(text), "principals { r { uids = [0];"
	    " anointments = [");
	for (i = 0; i < CAPBUNDLE_PRINCIPAL_MAX_NAMES; i++) {
		char one[64];

		snprintf(one, sizeof(one), "%s\"n.k%u\"", i ? ", " : "", i);
		strlcat(text, one, sizeof(text));
	}
	strlcat(text, "]; } }\n", sizeof(text));
	resolve(text, 0, NULL, 0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_PRINCIPAL_MAX_NAMES, g.nanointments);
	ATF_CHECK(capbundle_principal_holds(&g, "n.k0"));
	ATF_CHECK(capbundle_principal_holds(&g, "n.k31"));
	ATF_CHECK(!capbundle_principal_holds(&g, "n.k32"));

	text[strlen(text) - 7] = '\0';	/* strip "]; } }\n" */
	strlcat(text, ", \"n.kmore\"]; } }\n", sizeof(text));
	check_falls_back(text);
}

ATF_TC_WITHOUT_HEAD(grant_resolve_rejects_bad_args);
ATF_TC_BODY(grant_resolve_rejects_bad_args, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { GID_STAFF };

	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_principal_resolve(-1, 0, gids, 1,
	    stub_name2gid, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_principal_resolve(-1, 0, gids, 1, NULL, NULL,
	    &g));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_principal_resolve(-1, 0, NULL, 1,
	    stub_name2gid, NULL, &g));
	ATF_CHECK_EQ(EINVAL, errno);
	/* NULL members with zero count is fine. */
	ATF_CHECK_EQ(0, capbundle_principal_resolve(-1, 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(grant_lookups_null_safe);
ATF_TC_BODY(grant_lookups_null_safe, tc)
{
	struct capbundle_principal_grant g;

	ATF_CHECK(!capbundle_principal_holds(NULL, "a.b"));
	ATF_CHECK(!capbundle_principal_may_elevate(NULL, "a.b"));
	resolve("principals { r { uids = [0]; anointments = [\"*\"];"
	    " may_elevate = [\"*\"]; } }\n", 0, NULL, 0, &g);
	/* Even "*" never matches a NULL or empty name. */
	ATF_CHECK(!capbundle_principal_holds(&g, NULL));
	ATF_CHECK(!capbundle_principal_holds(&g, ""));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, NULL));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, ""));
	/* A corrupted count is clamped. */
	resolve("principals { r { uids = [0]; anointments = [\"a.b\"]; } }\n",
	    0, NULL, 0, &g);
	g.nanointments = CAPBUNDLE_PRINCIPAL_MAX_NAMES + 100;
	ATF_CHECK(capbundle_principal_holds(&g, "a.b"));
	ATF_CHECK(!capbundle_principal_holds(&g, "z.z"));
}

ATF_TC_WITHOUT_HEAD(is_admin_wrapper_tracks_admin_rights);
ATF_TC_BODY(is_admin_wrapper_tracks_admin_rights, tc)
{
	char path[64];
	gid_t ops[] = { GID_OPERATORS };
	int fd;

	/* P6/P8: root with admin_rights = false is not "admin". */
	write_policy(path, sizeof(path), "principals {\n"
	    "  root { uids = [0]; anointments = [\"system.switchboard.admin\"];"
	    " may_elevate = [\"*\"]; admin_rights = false; }\n"
	    "  ops { groups = [\"operators\"]; admin_rights = true; }\n"
	    "}\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_CHECK(!capbundle_principal_is_admin_resolved(fd, 0, NULL, 0,
	    stub_name2gid, NULL));
	/* An operator granted the bit without any reach is "admin". */
	ATF_CHECK(capbundle_principal_is_admin_resolved(fd, 7, ops, 1,
	    stub_name2gid, NULL));
	/* Unmatched, no default: not admin. */
	ATF_CHECK(!capbundle_principal_is_admin_resolved(fd, 8, NULL, 0,
	    stub_name2gid, NULL));
	(void)close(fd);

	/* New-format shipped policy through the wrapper. */
	write_policy(path, sizeof(path), shipped_policy);
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_CHECK(capbundle_principal_is_admin_resolved(fd, 0, NULL, 0,
	    stub_name2gid, NULL));
	ATF_CHECK(!capbundle_principal_is_admin_resolved(fd, 7, ops, 1,
	    stub_name2gid, NULL));
	(void)close(fd);

	/* NULL resolver still fails closed. */
	ATF_CHECK(!capbundle_principal_is_admin_resolved(-1, 0, NULL, 0, NULL,
	    NULL));
}

ATF_TC_WITHOUT_HEAD(grant_resolver_consulted_for_groups_only);
ATF_TC_BODY(grant_resolver_consulted_for_groups_only, tc)
{
	struct capbundle_principal_grant g;
	char path[64];
	int calls = 0;
	int fd;

	/* A uid-only policy never asks for a group name. */
	write_policy(path, sizeof(path),
	    "principals { r { uids = [0]; anointments = [\"a.b\"]; } }\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    stub_name2gid, &calls, &g));
	ATF_CHECK_EQ(0, calls);
	ATF_CHECK_EQ(1U, g.nanointments);
	(void)close(fd);

	/* The historical rule asks for exactly "wheel". */
	calls = 0;
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 5, NULL, 0,
	    stub_name2gid, &calls, &g));
	ATF_CHECK_EQ(1, calls);
	ATF_CHECK(g.from_default_rule);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, no_policy_defaults_to_root);
	ATF_TP_ADD_TC(tp, policy_grants_by_uid);
	ATF_TP_ADD_TC(tp, valid_policy_is_authoritative);
	ATF_TP_ADD_TC(tp, malformed_policy_fails_safe_to_default);
	ATF_TP_ADD_TC(tp, null_principal_is_not_admin);
	ATF_TP_ADD_TC(tp, policy_fd_grants_by_uid);
	ATF_TP_ADD_TC(tp, policy_fd_absent_defaults_to_root);
	ATF_TP_ADD_TC(tp, grant_admin_by_uid);
	ATF_TP_ADD_TC(tp, grant_admin_by_group);
	ATF_TP_ADD_TC(tp, grant_default_user_is_empty);
	ATF_TP_ADD_TC(tp, grant_operators_by_group);
	ATF_TP_ADD_TC(tp, grant_first_match_wins);
	ATF_TP_ADD_TC(tp, grant_default_fallback_regardless_of_position);
	ATF_TP_ADD_TC(tp, grant_no_match_no_default_is_empty);
	ATF_TP_ADD_TC(tp, grant_star_sets_all_flags);
	ATF_TP_ADD_TC(tp, grant_admin_rights_defaults);
	ATF_TP_ADD_TC(tp, grant_selectors_forms);
	ATF_TP_ADD_TC(tp, grant_legacy_admin_block);
	ATF_TP_ADD_TC(tp, grant_missing_file_uses_historical_rule);
	ATF_TP_ADD_TC(tp, grant_malformed_file_uses_historical_rule);
	ATF_TP_ADD_TC(tp, grant_unknown_key_in_entry_is_malformed);
	ATF_TP_ADD_TC(tp, grant_bad_types_are_malformed);
	ATF_TP_ADD_TC(tp, grant_invalid_names_are_malformed);
	ATF_TP_ADD_TC(tp, grant_too_many_names_is_malformed);
	ATF_TP_ADD_TC(tp, grant_resolve_rejects_bad_args);
	ATF_TP_ADD_TC(tp, grant_lookups_null_safe);
	ATF_TP_ADD_TC(tp, is_admin_wrapper_tracks_admin_rights);
	ATF_TP_ADD_TC(tp, grant_resolver_consulted_for_groups_only);
	return (atf_no_error());
}
