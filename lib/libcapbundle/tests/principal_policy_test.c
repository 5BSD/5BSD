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

ATF_TC_WITHOUT_HEAD(no_policy_is_least_privilege);
ATF_TC_BODY(no_policy_is_least_privilege, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);

	/* Absent policy: least privilege for EVERY principal, uid 0 included.
	 * uid 0 is not magic -- operator authority comes only from an explicit
	 * policy entry, so with no policy nobody (not even root) is admin.  A
	 * machine with no policy is administered from the pre-plane recovery
	 * shell, not a login session. */
	ATF_CHECK(!capbundle_principal_is_admin_at(&root,
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

ATF_TC_WITHOUT_HEAD(malformed_policy_fails_closed);
ATF_TC_BODY(malformed_policy_fails_closed, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);
	char path[64];

	/* An unparseable policy fails CLOSED to least privilege: nobody, not even
	 * root, is admin.  A corrupted policy must never silently grant authority;
	 * recovery is via the pre-plane single-user shell, not a login. */
	write_policy(path, sizeof(path), "admin { uids = [ this is not ucl \n");
	ATF_CHECK(!capbundle_principal_is_admin_at(&root, path));
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

ATF_TC_WITHOUT_HEAD(policy_fd_absent_is_least_privilege);
ATF_TC_BODY(policy_fd_absent_is_least_privilege, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);

	/* -1 fd (policy not delivered): least privilege for all, root included. */
	ATF_CHECK(!capbundle_principal_is_admin_fd(&root, -1));
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

ATF_TC_WITHOUT_HEAD(grant_missing_file_is_least_privilege);
ATF_TC_BODY(grant_missing_file_is_least_privilege, tc)
{
	struct capbundle_principal_grant g;
	gid_t wheel[] = { GID_STAFF, GID_WHEEL };
	gid_t staff[] = { GID_STAFF };

	/* No policy: least privilege for everyone, uid 0 and wheel included. */
	resolve(NULL, 0, NULL, 0, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);

	resolve(NULL, 1001, wheel, 2, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);

	resolve(NULL, 1001, staff, 1, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);

	/* An empty file is "no policy" too -- still least privilege for uid 0. */
	resolve("", 0, NULL, 0, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
}

ATF_TC_WITHOUT_HEAD(grant_malformed_file_is_least_privilege);
ATF_TC_BODY(grant_malformed_file_is_least_privilege, tc)
{
	struct capbundle_principal_grant g;
	gid_t staff[] = { GID_STAFF };

	/* Malformed policy fails CLOSED to least privilege, root included. */
	resolve("principals { admin { uids = [ this is not ucl \n",
	    0, NULL, 0, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);

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

	/*
	 * A malformed policy is DETECTED (from_default_rule set) and falls back
	 * to the least-privilege default -- empty even for uid 0.  The point of
	 * these tests is that the schema violation is caught; the fallback grant
	 * is fail-closed, so uid 0 gets nothing rather than the old root bypass.
	 */
	resolve(text, 0, NULL, 0, &g);
	ATF_CHECK_MSG(g.from_default_rule, "accepted: %s", text);
	check_empty_grant(&g);
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

	/* The least-privilege default rule grants nothing, so it consults the
	 * group resolver for no name at all. */
	calls = 0;
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 5, NULL, 0,
	    stub_name2gid, &calls, &g));
	ATF_CHECK_EQ(0, calls);
	ATF_CHECK(g.from_default_rule);
}

/* ---- edge cases and negative paths ------------------------------------ */

/* Resolve `uid` with the empty group set: the common case below. */
static void
resolve_uid(const char *text, uid_t uid, struct capbundle_principal_grant *g)
{

	resolve(text, uid, NULL, 0, g);
}

ATF_TC_WITHOUT_HEAD(principals_empty_block_everyone_empty);
ATF_TC_BODY(principals_empty_block_everyone_empty, tc)
{
	struct capbundle_principal_grant g;
	gid_t wheel[] = { GID_WHEEL };
	gid_t ops[] = { GID_OPERATORS, GID_STAFF };
	char path[64];
	int fd;

	/* Nothing matches, there is no fallback: an empty, authoritative grant
	 * for everyone -- root, wheel, operators, nobody. */
	resolve_uid("principals {}\n", 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	resolve("principals { }\n", 1001, wheel, 1, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	resolve("principals {\n}\n", 7, ops, 2, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	resolve_uid("principals {}\n", 65534, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	/* The admin wrapper agrees: root is not admin under an empty block. */
	write_policy(path, sizeof(path), "principals {}\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_CHECK(!capbundle_principal_is_admin_resolved(fd, 0, NULL, 0,
	    stub_name2gid, NULL));
	ATF_CHECK(!capbundle_principal_is_admin_resolved(fd, 1001, wheel, 1,
	    stub_name2gid, NULL));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(fallback_first_does_not_shadow_later_match);
ATF_TC_BODY(fallback_first_does_not_shadow_later_match, tc)
{
	struct capbundle_principal_grant g;
	gid_t ops[] = { GID_OPERATORS };

	/* An unnamed fallback (no selectors) listed first. */
	resolve_uid("principals {\n"
	    "  everyone { anointments = [\"a.everyone\"]; }\n"
	    "  me       { uids = [7]; anointments = [\"a.me\"]; }\n"
	    "}\n", 7, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.me", g.anointments[0]);
	ATF_CHECK(!capbundle_principal_holds(&g, "a.everyone"));
	/* ... and by group. */
	resolve("principals {\n"
	    "  everyone { anointments = [\"a.everyone\"]; }\n"
	    "  ops      { groups = [\"operators\"]; anointments = [\"a.ops\"]; }\n"
	    "}\n", 7, ops, 1, &g);
	ATF_CHECK_STREQ("a.ops", g.anointments[0]);
	/* A non-matching principal still lands on the fallback. */
	resolve_uid("principals {\n"
	    "  everyone { anointments = [\"a.everyone\"]; }\n"
	    "  me       { uids = [7]; anointments = [\"a.me\"]; }\n"
	    "}\n", 8, &g);
	ATF_CHECK_STREQ("a.everyone", g.anointments[0]);
	ATF_CHECK(!g.from_default_rule);

	/* A fallback named "default" first, then a "*" match later: the
	 * match wins with its full grant. */
	resolve_uid("principals {\n"
	    "  default { anointments = []; }\n"
	    "  root    { uids = [0]; anointments = [\"*\"]; }\n"
	    "}\n", 0, &g);
	check_full_admin_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

/*
 * An entry named "default" is a fallback by name even when it carries
 * selectors; when its selectors match it is an ordinary match.  Document.
 */
ATF_TC_WITHOUT_HEAD(default_named_entry_with_selectors_documented);
ATF_TC_BODY(default_named_entry_with_selectors_documented, tc)
{
	struct capbundle_principal_grant g;

	/* uid 5 matches "default" by selector -> a.def; uid 7 matches
	 * nothing but "default" is the fallback by name -> a.def too. */
	resolve_uid("principals {\n"
	    "  default { uids = [5]; anointments = [\"a.def\"]; }\n"
	    "  other   { uids = [9]; anointments = [\"a.other\"]; }\n"
	    "}\n", 5, &g);
	ATF_CHECK_STREQ("a.def", g.anointments[0]);
	resolve_uid("principals {\n"
	    "  default { uids = [5]; anointments = [\"a.def\"]; }\n"
	    "  other   { uids = [9]; anointments = [\"a.other\"]; }\n"
	    "}\n", 7, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.def", g.anointments[0]);
	/* An entry with an empty uids list is neither a match nor a
	 * fallback: it is dead, and the principal gets nothing. */
	resolve_uid("principals {\n"
	    "  dead { uids = []; anointments = [\"a.dead\"]; }\n"
	    "}\n", 7, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	resolve_uid("principals {\n"
	    "  dead { groups = []; anointments = [\"a.dead\"]; }\n"
	    "}\n", 7, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(uid_vs_group_file_order_wins);
ATF_TC_BODY(uid_vs_group_file_order_wins, tc)
{
	struct capbundle_principal_grant g;
	gid_t ops[] = { GID_OPERATORS };

	/* uid entry first: uid wins. */
	resolve("principals {\n"
	    "  me  { uids = [7]; anointments = [\"a.me\"]; may_elevate = [\"e.me\"]; }\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; admin_rights = true; }\n"
	    "}\n", 7, ops, 1, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.me", g.anointments[0]);
	ATF_CHECK(capbundle_principal_may_elevate(&g, "e.me"));
	ATF_CHECK(!g.admin_rights);
	/* group entry first: group wins; nothing from the uid entry leaks. */
	resolve("principals {\n"
	    "  ops { groups = [\"operators\"]; anointments = [\"a.ops\"]; admin_rights = true; }\n"
	    "  me  { uids = [7]; anointments = [\"a.me\"]; may_elevate = [\"e.me\"]; }\n"
	    "}\n", 7, ops, 1, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.ops", g.anointments[0]);
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "e.me"));
	ATF_CHECK(g.admin_rights);
	/* Grants never merge: the second matching entry contributes nothing. */
	ATF_CHECK(!capbundle_principal_holds(&g, "a.me"));
}

ATF_TC_WITHOUT_HEAD(uid_in_two_entries_first_wins);
ATF_TC_BODY(uid_in_two_entries_first_wins, tc)
{
	struct capbundle_principal_grant g;

	resolve_uid("principals {\n"
	    "  narrow { uids = [7]; anointments = [\"a.narrow\"]; }\n"
	    "  wide   { uids = [7]; anointments = [\"*\"]; admin_rights = true; }\n"
	    "}\n", 7, &g);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.narrow", g.anointments[0]);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(!g.admin_rights);
	/* Reversed: the wide one wins. */
	resolve_uid("principals {\n"
	    "  wide   { uids = [7]; anointments = [\"*\"]; admin_rights = true; }\n"
	    "  narrow { uids = [7]; anointments = [\"a.narrow\"]; }\n"
	    "}\n", 7, &g);
	check_full_admin_grant(&g);
	/* Same uid listed twice in one entry is not a problem. */
	resolve_uid("principals { r { uids = [7, 7]; anointments = [\"a.b\"]; } }\n",
	    7, &g);
	ATF_CHECK_STREQ("a.b", g.anointments[0]);
}

ATF_TC_WITHOUT_HEAD(admin_rights_non_boolean_is_malformed);
ATF_TC_BODY(admin_rights_non_boolean_is_malformed, tc)
{
	struct capbundle_principal_grant g;

	check_falls_back("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = \"yes\"; } }\n");
	check_falls_back("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = \"false\"; } }\n");
	check_falls_back("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = 0; } }\n");
	check_falls_back("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = [true]; } }\n");
	check_falls_back("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = null; } }\n");
	check_falls_back("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = { on = true }; } }\n");
	/* ... even in an entry that is not the one chosen. */
	check_falls_back("principals {\n"
	    "  r   { uids = [0]; anointments = [\"*\"]; }\n"
	    "  ops { groups = [\"operators\"]; admin_rights = \"yes\"; }\n"
	    "}\n");
	/* Unquoted yes/no/on/off are UCL booleans and are honoured. */
	resolve_uid("principals { r { uids = [0]; anointments = [\"a.b\"];"
	    " admin_rights = yes; } }\n", 0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(g.admin_rights);
	resolve_uid("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = off; } }\n", 0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(!g.admin_rights);
}

ATF_TC_WITHOUT_HEAD(anointments_star_mixed_with_names);
ATF_TC_BODY(anointments_star_mixed_with_names, tc)
{
	struct capbundle_principal_grant g;

	/* "*" does not excuse an invalid name beside it: the file is
	 * malformed and falls back. */
	check_falls_back("principals { r { uids = [0];"
	    " anointments = [\"*\", \"x\"]; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " anointments = [\"x\", \"*\"]; } }\n");
	check_falls_back("principals { r { uids = [0];"
	    " may_elevate = [\"*\", \"x\"]; } }\n");
	/* "*" beside valid names: all wins, the names are still recorded. */
	resolve_uid("principals { r { uids = [0];"
	    " anointments = [\"*\", \"a.x\"]; } }\n", 0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.x", g.anointments[0]);
	ATF_CHECK(g.admin_rights);
	ATF_CHECK(capbundle_principal_holds(&g, "a.x"));
	ATF_CHECK(capbundle_principal_holds(&g, "never.listed"));
	/* Repeated "*" is folded like any duplicate. */
	resolve_uid("principals { r { uids = [0];"
	    " anointments = [\"*\", \"*\", \"a.x\", \"a.x\"]; } }\n", 0, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK_EQ(1U, g.nanointments);
	/* "*" in may_elevate does not bleed into anointments, nor back. */
	resolve_uid("principals { r { uids = [0]; anointments = [\"a.x\"];"
	    " may_elevate = [\"*\"]; } }\n", 0, &g);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(g.elevate_all);
	ATF_CHECK(!capbundle_principal_holds(&g, "b.y"));
	ATF_CHECK(capbundle_principal_may_elevate(&g, "b.y"));
	resolve_uid("principals { r { uids = [0]; anointments = [\"*\"];"
	    " may_elevate = [\"e.x\"]; } }\n", 0, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(!g.elevate_all);
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "b.y"));
	ATF_CHECK(capbundle_principal_may_elevate(&g, "e.x"));
}

ATF_TC_WITHOUT_HEAD(may_elevate_forms);
ATF_TC_BODY(may_elevate_forms, tc)
{
	struct capbundle_principal_grant g;
	static const char *const probes[] = {
		"system.notify.system", "a.b", "e.x", "*", "" };
	size_t i;

	/* Scalar "*": everything may be elevated to. */
	resolve_uid("principals { r { uids = [0]; may_elevate = \"*\"; } }\n",
	    0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(g.elevate_all);
	ATF_CHECK_EQ(0U, g.nmay_elevate);
	ATF_CHECK(!g.admin_rights);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(capbundle_principal_may_elevate(&g, "system.notify.system"));
	ATF_CHECK(capbundle_principal_may_elevate(&g, "a.b"));
	/* Literal "*" and "" are never names, even under elevate_all. */
	ATF_CHECK(!capbundle_principal_may_elevate(&g, ""));

	/* Explicit empty list: nothing may be elevated to. */
	resolve_uid("principals { r { uids = [0]; anointments = [\"a.b\"];"
	    " may_elevate = []; } }\n", 0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(!g.elevate_all);
	ATF_CHECK_EQ(0U, g.nmay_elevate);
	for (i = 0; i < nitems(probes); i++)
		ATF_CHECK_MSG(!capbundle_principal_may_elevate(&g, probes[i]),
		    "elevates to '%s'", probes[i]);
	/* Absent: the same. */
	resolve_uid("principals { r { uids = [0]; anointments = [\"a.b\"]; } }\n",
	    0, &g);
	ATF_CHECK(!g.elevate_all);
	ATF_CHECK_EQ(0U, g.nmay_elevate);
	for (i = 0; i < nitems(probes); i++)
		ATF_CHECK(!capbundle_principal_may_elevate(&g, probes[i]));
	/* Scalar name. */
	resolve_uid("principals { r { uids = [0]; may_elevate = \"e.x\"; } }\n",
	    0, &g);
	ATF_CHECK_EQ(1U, g.nmay_elevate);
	ATF_CHECK(capbundle_principal_may_elevate(&g, "e.x"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "e.y"));
	/* Holding a name and being able to elevate to it are independent. */
	ATF_CHECK(!capbundle_principal_holds(&g, "e.x"));
	/* Empty string and bad forms are malformed. */
	check_falls_back("principals { r { uids = [0]; may_elevate = \"\"; } }\n");
	check_falls_back("principals { r { uids = [0]; may_elevate = [\"\"]; } }\n");
	check_falls_back("principals { r { uids = [0]; may_elevate = 7; } }\n");
	check_falls_back("principals { r { uids = [0]; may_elevate = [7]; } }\n");
	check_falls_back("principals { r { uids = [0]; may_elevate = [[\"a.b\"]]; } }\n");
	check_falls_back("principals { r { uids = [0]; may_elevate = null; } }\n");
}

ATF_TC_WITHOUT_HEAD(selector_bad_values_are_malformed);
ATF_TC_BODY(selector_bad_values_are_malformed, tc)
{
	struct capbundle_principal_grant g;

	check_falls_back("principals { r { uids = [-1]; anointments = [\"a.b\"]; } }\n");
	check_falls_back("principals { r { uids = [\"0\"]; anointments = [\"a.b\"]; } }\n");
	check_falls_back("principals { r { uids = [0, \"7\"]; } }\n");
	check_falls_back("principals { r { uids = \"root\"; } }\n");
	check_falls_back("principals { r { uids = [1.5]; } }\n");
	check_falls_back("principals { r { uids = 1.5; } }\n");
	check_falls_back("principals { r { uids = true; } }\n");
	check_falls_back("principals { r { uids = [true]; } }\n");
	check_falls_back("principals { r { uids = null; } }\n");
	check_falls_back("principals { r { uids = [null]; } }\n");
	check_falls_back("principals { r { uids = { id = 0 }; } }\n");
	check_falls_back("principals { r { uids = [[0]]; } }\n");
	/* Past uid_t. */
	check_falls_back("principals { r { uids = [4294967296]; } }\n");
	check_falls_back("principals { r { uids = [9223372036854775807]; } }\n");
	check_falls_back("principals { r { groups = [0]; anointments = [\"a.b\"]; } }\n");
	check_falls_back("principals { r { groups = 0; } }\n");
	check_falls_back("principals { r { groups = [true]; } }\n");
	check_falls_back("principals { r { groups = [null]; } }\n");
	check_falls_back("principals { r { groups = null; } }\n");
	check_falls_back("principals { r { groups = [\"wheel\", \"\"]; } }\n");
	check_falls_back("principals { r { groups = [[\"wheel\"]]; } }\n");
	check_falls_back("principals { r { groups = { name = \"wheel\" }; } }\n");
	/* The largest uid_t is representable and matches that principal. */
	resolve_uid("principals { r { uids = [4294967295]; anointments = [\"a.max\"]; } }\n",
	    (uid_t)4294967295U, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK_STREQ("a.max", g.anointments[0]);
	resolve_uid("principals { r { uids = [4294967295]; anointments = [\"a.max\"]; } }\n",
	    0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
}

ATF_TC_WITHOUT_HEAD(root_in_non_admin_entry_gets_nothing);
ATF_TC_BODY(root_in_non_admin_entry_gets_nothing, tc)
{
	struct capbundle_principal_grant g;
	gid_t wheel[] = { GID_WHEEL };
	char path[64];
	int fd;

	/* Root is just a principal: an entry naming uid 0 with an empty set
	 * gives root nothing, even if root is also in wheel. */
	resolve_uid("principals {\n"
	    "  root  { uids = [0]; anointments = []; }\n"
	    "  admin { groups = [\"wheel\"]; anointments = [\"*\"]; }\n"
	    "}\n", 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	resolve("principals {\n"
	    "  root  { uids = [0]; anointments = []; }\n"
	    "  admin { groups = [\"wheel\"]; anointments = [\"*\"]; }\n"
	    "}\n", 0, wheel, 1, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	/* No anointments key at all: the same. */
	resolve_uid("principals { root { uids = [0]; } }\n", 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);

	write_policy(path, sizeof(path),
	    "principals { root { uids = [0]; anointments = []; } }\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_CHECK(!capbundle_principal_is_admin_resolved(fd, 0, wheel, 1,
	    stub_name2gid, NULL));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(star_with_admin_rights_false);
ATF_TC_BODY(star_with_admin_rights_false, tc)
{
	struct capbundle_principal_grant g;
	char path[64];
	int fd;

	write_policy(path, sizeof(path), "principals { r { uids = [0];"
	    " anointments = [\"*\"]; admin_rights = false; } }\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(!g.admin_rights);
	ATF_CHECK_EQ(0U, g.nanointments);
	ATF_CHECK(capbundle_principal_holds(&g, "system.notify.system"));
	ATF_CHECK(capbundle_principal_holds(&g, "anything.at.all"));
	ATF_CHECK(!g.elevate_all);
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "anything.at.all"));
	/* Reach without the bypass bit: not "admin". */
	ATF_CHECK(!capbundle_principal_is_admin_resolved(fd, 0, NULL, 0,
	    stub_name2gid, NULL));
	(void)close(fd);
	/* Scalar form, same result. */
	resolve_uid("principals { r { uids = [0]; anointments = \"*\";"
	    " admin_rights = false; } }\n", 0, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK(!g.admin_rights);
}

ATF_TC_WITHOUT_HEAD(name_length_and_wildcard_fragments);
ATF_TC_BODY(name_length_and_wildcard_fragments, tc)
{
	struct capbundle_principal_grant g;
	char text[512], name[80];
	static const char *const frags[] = {
		"system.*", "*.system", "a.*.b", "sys*.x", "a.b*", "*a.b",
		"**", "*.*", " *", "* ", "a.b.*", "a.*", "*.", ".*",
	};
	size_t i;

	/* 63: accepted in both lists. */
	memset(name, 'b', sizeof(name));
	name[0] = 'a';
	name[1] = '.';
	name[CAPBUNDLE_LABEL_MAX - 1] = '\0';
	snprintf(text, sizeof(text), "principals { r { uids = [0];"
	    " anointments = [\"%s\"]; may_elevate = [\"%s\"]; } }\n", name, name);
	resolve_uid(text, 0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_EQ(1U, g.nmay_elevate);
	ATF_CHECK_STREQ(name, g.anointments[0]);
	ATF_CHECK_STREQ(name, g.may_elevate[0]);
	ATF_CHECK(capbundle_principal_holds(&g, name));
	ATF_CHECK(capbundle_principal_may_elevate(&g, name));
	/* 64: malformed in either list. */
	name[CAPBUNDLE_LABEL_MAX - 1] = 'b';
	name[CAPBUNDLE_LABEL_MAX] = '\0';
	snprintf(text, sizeof(text), "principals { r { uids = [0];"
	    " anointments = [\"%s\"]; } }\n", name);
	check_falls_back(text);
	snprintf(text, sizeof(text), "principals { r { uids = [0];"
	    " may_elevate = [\"%s\"]; } }\n", name);
	check_falls_back(text);
	snprintf(text, sizeof(text), "principals { r { uids = [0];"
	    " anointments = [\"*\", \"%s\"]; } }\n", name);
	check_falls_back(text);
	/* Wildcard fragments are neither names nor the wildcard. */
	for (i = 0; i < nitems(frags); i++) {
		snprintf(text, sizeof(text), "principals { r { uids = [0];"
		    " anointments = [\"%s\"]; } }\n", frags[i]);
		check_falls_back(text);
		snprintf(text, sizeof(text), "principals { r { uids = [0];"
		    " may_elevate = \"%s\"; } }\n", frags[i]);
		check_falls_back(text);
	}
}

/* Write a syntactically valid policy padded with a comment to `size` bytes. */
static int
open_policy_of_size(size_t size)
{
	static const char head[] =
	    "principals { r { uids = [0]; anointments = [\"a.cap\"]; } }\n# ";
	char path[64];
	char *buf;
	int fd;

	ATF_REQUIRE(size > sizeof(head) + 1);
	buf = malloc(size);
	ATF_REQUIRE(buf != NULL);
	memcpy(buf, head, sizeof(head) - 1);
	memset(buf + sizeof(head) - 1, 'x', size - sizeof(head));
	buf[size - 1] = '\n';
	strlcpy(path, "/tmp/cappolicy.XXXXXX", sizeof(path));
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_REQUIRE_EQ((ssize_t)size, write(fd, buf, size));
	free(buf);
	return (fd);
}

ATF_TC_WITHOUT_HEAD(policy_size_cap);
ATF_TC_BODY(policy_size_cap, tc)
{
	struct capbundle_principal_grant g;
	int fd;

	/* Exactly the cap: read and applied. */
	fd = open_policy_of_size(CAPBUNDLE_MAX_UCL_SIZE);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.cap", g.anointments[0]);
	ATF_CHECK(!g.anoint_all);
	(void)close(fd);

	/* One byte over: unusable, falls back to least privilege (root gets nothing). */
	fd = open_policy_of_size(CAPBUNDLE_MAX_UCL_SIZE + 1);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 1001, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(policy_fd_not_regular_falls_back);
ATF_TC_BODY(policy_fd_not_regular_falls_back, tc)
{
	struct capbundle_principal_grant g;
	int fd, pfd[2];

	/* A directory. */
	fd = open("/", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
	(void)close(fd);
	/* A pipe with policy text in it: not a regular file. */
	ATF_REQUIRE_EQ(0, pipe(pfd));
	ATF_REQUIRE(write(pfd[1], "principals {}\n", 14) == 14);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(pfd[0], 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	(void)close(pfd[0]);
	(void)close(pfd[1]);
	/* A descriptor that is not open. */
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(12345, 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-7, 1001, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
	/* /dev/null: regular? no -- a character device, so fallback. */
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 0, NULL, 0,
	    stub_name2gid, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(holds_and_may_elevate_exact_match_only);
ATF_TC_BODY(holds_and_may_elevate_exact_match_only, tc)
{
	struct capbundle_principal_grant g;

	resolve_uid("principals { r { uids = [0];"
	    " anointments = [\"system.notify\", \"a.b\"];"
	    " may_elevate = [\"system.notify\"]; } }\n", 0, &g);
	ATF_CHECK(capbundle_principal_holds(&g, "system.notify"));
	ATF_CHECK(capbundle_principal_may_elevate(&g, "system.notify"));
	/* Neither prefix nor suffix nor case-fold nor trailing junk. */
	ATF_CHECK(!capbundle_principal_holds(&g, "system.notify.system"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system"));
	ATF_CHECK(!capbundle_principal_holds(&g, "notify"));
	ATF_CHECK(!capbundle_principal_holds(&g, "System.Notify"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system.notify "));
	ATF_CHECK(!capbundle_principal_holds(&g, " system.notify"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system.notify."));
	ATF_CHECK(!capbundle_principal_holds(&g, ".system.notify"));
	ATF_CHECK(!capbundle_principal_holds(&g, "a.b.c"));
	ATF_CHECK(!capbundle_principal_holds(&g, "a"));
	ATF_CHECK(!capbundle_principal_holds(&g, "*"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "system.notify.system"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "system"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "a.b"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "*"));
	/* The reverse: holding the longer name says nothing about the prefix. */
	resolve_uid("principals { r { uids = [0];"
	    " anointments = [\"system.notify.system\"]; } }\n", 0, &g);
	ATF_CHECK(capbundle_principal_holds(&g, "system.notify.system"));
	ATF_CHECK(!capbundle_principal_holds(&g, "system.notify"));
	/* NULL grant / NULL or empty name. */
	ATF_CHECK(!capbundle_principal_holds(NULL, "system.notify.system"));
	ATF_CHECK(!capbundle_principal_holds(NULL, NULL));
	ATF_CHECK(!capbundle_principal_holds(&g, NULL));
	ATF_CHECK(!capbundle_principal_holds(&g, ""));
	ATF_CHECK(!capbundle_principal_may_elevate(NULL, "a.b"));
	ATF_CHECK(!capbundle_principal_may_elevate(NULL, NULL));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, NULL));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, ""));
	/* A zeroed grant holds nothing. */
	memset(&g, 0, sizeof(g));
	ATF_CHECK(!capbundle_principal_holds(&g, "a.b"));
	ATF_CHECK(!capbundle_principal_may_elevate(&g, "a.b"));
}

/*
 * When both the legacy admin block and a principals block are present the
 * principals block is authoritative and the legacy block is ignored
 * entirely -- it is not even validated.  Document that precedence.
 */
ATF_TC_WITHOUT_HEAD(legacy_and_principals_both_present);
ATF_TC_BODY(legacy_and_principals_both_present, tc)
{
	struct capbundle_principal_grant g;
	gid_t wheel[] = { GID_WHEEL };

	/* Legacy would make root admin; principals {} says nothing does. */
	resolve_uid("admin { uids = [0]; groups = [\"wheel\"]; }\n"
	    "principals {}\n", 0, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	resolve("principals {}\nadmin { uids = [0]; groups = [\"wheel\"]; }\n",
	    1001, wheel, 1, &g);
	check_empty_grant(&g);
	ATF_CHECK(!g.from_default_rule);
	/* Legacy names root, principals names someone else: principals. */
	resolve_uid("admin { uids = [0]; }\n"
	    "principals { ops { uids = [7]; anointments = [\"a.ops\"]; } }\n",
	    0, &g);
	check_empty_grant(&g);
	resolve_uid("admin { uids = [0]; }\n"
	    "principals { ops { uids = [7]; anointments = [\"a.ops\"]; } }\n",
	    7, &g);
	ATF_CHECK_STREQ("a.ops", g.anointments[0]);
	/* A malformed legacy block beside a valid principals block does not
	 * trigger the fallback: it is simply not looked at. */
	resolve_uid("admin = 7;\n"
	    "principals { ops { uids = [7]; anointments = [\"a.ops\"]; } }\n",
	    7, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK_STREQ("a.ops", g.anointments[0]);
	resolve_uid("admin { uids = \"root\"; bogus = 1; }\n"
	    "principals { ops { uids = [7]; anointments = [\"a.ops\"]; } }\n",
	    0, &g);
	ATF_CHECK(!g.from_default_rule);
	check_empty_grant(&g);
	/* Whereas a malformed principals block beside a valid legacy block
	 * does fall back (principals is looked at first). */
	check_falls_back("admin { uids = [0]; }\nprincipals = 7;\n");
	check_falls_back("admin { uids = [0]; }\nprincipals { r = 1; }\n");
}

ATF_TC_WITHOUT_HEAD(unknown_group_never_matches_gid_minus_one);
ATF_TC_BODY(unknown_group_never_matches_gid_minus_one, tc)
{
	struct capbundle_principal_grant g;
	gid_t weird[] = { (gid_t)-1, GID_STAFF };
	int calls = 0;
	char path[64];
	int fd;

	/* The stub returns (gid_t)-1 for "nosuch"; a member list that happens
	 * to contain (gid_t)-1 must not match it. */
	write_policy(path, sizeof(path), "principals {\n"
	    "  ghost { groups = [\"nosuch\"]; anointments = [\"*\"]; }\n"
	    "  default { anointments = [\"a.default\"]; }\n"
	    "}\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)unlink(path);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, 7, weird, 2,
	    stub_name2gid, &calls, &g));
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK_EQ(1U, g.nanointments);
	ATF_CHECK_STREQ("a.default", g.anointments[0]);
	ATF_CHECK_EQ(1, calls);
	(void)close(fd);
	/* The historical rule's "wheel" lookup is equally guarded. */
	calls = 0;
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 7, weird, 2,
	    stub_name2gid, &calls, &g));
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
}

/*
 * Repeated keys.  The policy parser runs libucl without implicit arrays
 * (like the unit-file parser): a repeated array or object key -- a second
 * anointments list, a second uids list, a second entry of the same name, a
 * second principals block -- is a parse error, so the whole file is
 * malformed and the historical rule applies (visible as from_default_rule).
 * A repeated scalar key is last-wins under libucl, which is at least the
 * override an operator expects; pin both so a change is deliberate.
 */
ATF_TC_WITHOUT_HEAD(repeated_keys_are_malformed);
ATF_TC_BODY(repeated_keys_are_malformed, tc)
{
	struct capbundle_principal_grant g;
	static const char *const malformed[] = {
		"principals { r { uids = [0];"
		" anointments = [\"a.b\"]; anointments = [\"c.d\"]; } }\n",
		"principals { r { uids = [7]; uids = [0];"
		" anointments = [\"a.b\"]; } }\n",
		"principals {\n"
		"  r { uids = [0]; anointments = [\"a.first\"]; }\n"
		"  r { uids = [0]; anointments = [\"a.second\"]; }\n"
		"}\n",
		"principals { r { uids = [0]; } }\n"
		"principals { r { uids = [0]; anointments = [\"a.b\"]; } }\n",
		/* A macro is refused: policy must not pull in other files. */
		".include \"/etc/passwd\"\nprincipals { r { uids = [0]; } }\n",
	};
	unsigned i;

	for (i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
		/* Malformed is detected; fallback is least privilege for everyone. */
		resolve_uid(malformed[i], 7, &g);
		ATF_CHECK_MSG(g.from_default_rule, "text %u not malformed", i);
		check_empty_grant(&g);
		/* uid 0 too: fail-closed, no root bypass. */
		resolve_uid(malformed[i], 0, &g);
		ATF_CHECK(g.from_default_rule);
		check_empty_grant(&g);
	}
	/*
	 * A repeated scalar-string key is the one shape libucl still folds
	 * into a list: both names are seen, as if written as an array.  A
	 * repeated boolean is a parse error like the arrays above.
	 */
	resolve_uid("principals { r { uids = [0];"
	    " anointments = \"a.b\"; anointments = \"c.d\"; } }\n", 0, &g);
	ATF_CHECK(!g.from_default_rule);
	ATF_CHECK_EQ(2U, g.nanointments);
	ATF_CHECK(capbundle_principal_holds(&g, "a.b"));
	ATF_CHECK(capbundle_principal_holds(&g, "c.d"));
	resolve_uid("principals { r { uids = [0]; anointments = [\"*\"];"
	    " admin_rights = true; admin_rights = false; } }\n", 7, &g);
	ATF_CHECK(g.from_default_rule);
	check_empty_grant(&g);
}

ATF_TC_WITHOUT_HEAD(declared_names_unions_grants_and_may_elevate);
ATF_TC_BODY(declared_names_unions_grants_and_may_elevate, tc)
{
	char names[CAPBUNDLE_PRINCIPAL_MAX_NAMES * 4][CAPBUNDLE_LABEL_MAX];
	char path[64];
	unsigned n, i;
	int fd, saw_op = 0, saw_elev = 0, saw_star = 0;

	write_policy(path, sizeof(path),
	    "principals {\n"
	    "  admin { uids = [0]; anointments = [\"*\"]; admin_rights = true; }\n"
	    "  operators { groups = [\"operators\"];"
	    " anointments = [\"system.trace.client\"];"
	    " may_elevate = [\"system.notify.system\"]; }\n"
	    "  default { anointments = []; }\n"
	    "}\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	n = 4242;
	ATF_REQUIRE_EQ(0, capbundle_principal_declared_names(fd, names,
	    nitems(names), &n));
	(void)close(fd);
	(void)unlink(path);
	for (i = 0; i < n; i++) {
		if (strcmp(names[i], "system.trace.client") == 0)
			saw_op = 1;
		else if (strcmp(names[i], "system.notify.system") == 0)
			saw_elev = 1;
		else if (strcmp(names[i], "*") == 0)
			saw_star = 1;
	}
	ATF_CHECK_MSG(saw_op, "anointments grant not enumerated");
	ATF_CHECK_MSG(saw_elev, "may_elevate name not enumerated");
	ATF_CHECK_MSG(!saw_star, "the wildcard must never be enumerated");
	ATF_CHECK_EQ(2, n);	/* exactly the two specific names, deduped */
}

ATF_TC_WITHOUT_HEAD(declared_names_absent_policy_is_empty);
ATF_TC_BODY(declared_names_absent_policy_is_empty, tc)
{
	char names[8][CAPBUNDLE_LABEL_MAX];
	unsigned n = 4242;

	/* A closed descriptor / missing policy yields an empty set, not error. */
	ATF_CHECK_EQ(0, capbundle_principal_declared_names(-1, names,
	    nitems(names), &n));
	ATF_CHECK_EQ(0, n);
	ATF_CHECK_ERRNO(EINVAL,
	    capbundle_principal_declared_names(-1, NULL, 8, &n) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, no_policy_is_least_privilege);
	ATF_TP_ADD_TC(tp, policy_grants_by_uid);
	ATF_TP_ADD_TC(tp, valid_policy_is_authoritative);
	ATF_TP_ADD_TC(tp, malformed_policy_fails_closed);
	ATF_TP_ADD_TC(tp, null_principal_is_not_admin);
	ATF_TP_ADD_TC(tp, policy_fd_grants_by_uid);
	ATF_TP_ADD_TC(tp, policy_fd_absent_is_least_privilege);
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
	ATF_TP_ADD_TC(tp, grant_missing_file_is_least_privilege);
	ATF_TP_ADD_TC(tp, grant_malformed_file_is_least_privilege);
	ATF_TP_ADD_TC(tp, grant_unknown_key_in_entry_is_malformed);
	ATF_TP_ADD_TC(tp, grant_bad_types_are_malformed);
	ATF_TP_ADD_TC(tp, grant_invalid_names_are_malformed);
	ATF_TP_ADD_TC(tp, grant_too_many_names_is_malformed);
	ATF_TP_ADD_TC(tp, grant_resolve_rejects_bad_args);
	ATF_TP_ADD_TC(tp, grant_lookups_null_safe);
	ATF_TP_ADD_TC(tp, is_admin_wrapper_tracks_admin_rights);
	ATF_TP_ADD_TC(tp, grant_resolver_consulted_for_groups_only);
	ATF_TP_ADD_TC(tp, principals_empty_block_everyone_empty);
	ATF_TP_ADD_TC(tp, fallback_first_does_not_shadow_later_match);
	ATF_TP_ADD_TC(tp, default_named_entry_with_selectors_documented);
	ATF_TP_ADD_TC(tp, uid_vs_group_file_order_wins);
	ATF_TP_ADD_TC(tp, uid_in_two_entries_first_wins);
	ATF_TP_ADD_TC(tp, admin_rights_non_boolean_is_malformed);
	ATF_TP_ADD_TC(tp, anointments_star_mixed_with_names);
	ATF_TP_ADD_TC(tp, may_elevate_forms);
	ATF_TP_ADD_TC(tp, selector_bad_values_are_malformed);
	ATF_TP_ADD_TC(tp, root_in_non_admin_entry_gets_nothing);
	ATF_TP_ADD_TC(tp, star_with_admin_rights_false);
	ATF_TP_ADD_TC(tp, name_length_and_wildcard_fragments);
	ATF_TP_ADD_TC(tp, policy_size_cap);
	ATF_TP_ADD_TC(tp, policy_fd_not_regular_falls_back);
	ATF_TP_ADD_TC(tp, holds_and_may_elevate_exact_match_only);
	ATF_TP_ADD_TC(tp, legacy_and_principals_both_present);
	ATF_TP_ADD_TC(tp, unknown_group_never_matches_gid_minus_one);
	ATF_TP_ADD_TC(tp, repeated_keys_are_malformed);
	ATF_TP_ADD_TC(tp, declared_names_unions_grants_and_may_elevate);
	ATF_TP_ADD_TC(tp, declared_names_absent_policy_is_empty);
	return (atf_no_error());
}
