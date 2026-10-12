/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The bundle registry's scan policy, driven on real bundle directories
 * (root-owned, as trusted_tree requires): user conflicts are quarantined
 * rather than fatal, a registered bundle that fails validation mid-rescan
 * keeps its previous registration, a differently spelled root still finds it,
 * and a vanished System root retains the previous registry.
 */
#include <sys/stat.h>

#include <atf-c.h>
#include <capimage.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "switchboard.h"
#include "bundle_policy.h"

const char *switchboard_bundle_dir_system;
const char *switchboard_bundle_dir_user;
const char *switchboard_users_dir = "/nonexistent/switchboard-users";
struct switchboard_state sd;

static char sysroot[PATH_MAX], userroot[PATH_MAX];

/* Test only the system-policy input; parsing and verification stay real.
 * Never modify the running host's /etc/capability policy. */
static bool signatures_required;
int
capimage_signatures_required(bool *required, char *error, size_t size)
{
	(void)error;
	(void)size;
	*required = signatures_required;
	return (0);
}


static void
roots(void)
{
	char cwd[PATH_MAX];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(sysroot, sizeof(sysroot), "%s/System", cwd);
	snprintf(userroot, sizeof(userroot), "%s/Apps", cwd);
	ATF_REQUIRE_EQ(0, mkdir(sysroot, 0755));
	ATF_REQUIRE_EQ(0, mkdir(userroot, 0755));
	switchboard_bundle_dir_system = sysroot;
	switchboard_bundle_dir_user = userroot;
	setenv("SWITCHBOARD_DISABLED_PATH", "/nonexistent/disabled", 1);
}

static void
writef(const char *path, const char *text, mode_t mode)
{
	FILE *f = fopen(path, "w");

	ATF_REQUIRE(f != NULL);
	fputs(text, f);
	fclose(f);
	ATF_REQUIRE_EQ(0, chmod(path, mode));
}

/* A one-unit bundle whose unit provides `ipc` (empty: boot-activated). */
static void
mkbundle(const char *root, const char *name, const char *bid, const char *unit,
    const char *ipc)
{
	char p[PATH_MAX], t[1024];

	snprintf(p, sizeof(p), "%s/%s.cap/Units/%s.unit/bin", root, name, unit);
	ATF_REQUIRE_EQ(0, system(({ static char cmd[PATH_MAX + 16];
	    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", p); cmd; })));
	snprintf(p, sizeof(p), "%s/%s.cap/Bundle.ucl", root, name);
	snprintf(t, sizeof(t), "schema = \"org.5bsd.capability-bundle\";\n"
	    "bundle_id = \"%s\";\nversion = \"1.0.0\";\n"
	    "sequence = 1;\nauthor = \"t\";\npublisher = \"org.test\";\n"
	    "units = [\"%s\"];\n", bid, unit);
	writef(p, t, 0644);
	snprintf(p, sizeof(p), "%s/%s.cap/Units/%s.unit/Unit.ucl", root, name, unit);
	if (ipc[0] != '\0')
		snprintf(t, sizeof(t), "activation { ipc = [\"%s\"]; }\n"
		    "program = \"%s\";\nuser = \"root\";\n", ipc, unit);
	else
		snprintf(t, sizeof(t), "activation { boot = true; }\n"
		    "program = \"%s\";\nuser = \"root\";\n", unit);
	writef(p, t, 0644);
	snprintf(p, sizeof(p), "%s/%s.cap/Units/%s.unit/bin/%s", root, name, unit,
	    unit);
	writef(p, "#!/bin/sh\nexit 0\n", 0555);
}

ATF_TC(user_conflicts_are_quarantined_not_fatal);
ATF_TC_HEAD(user_conflicts_are_quarantined_not_fatal, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(user_conflicts_are_quarantined_not_fatal, tc)
{
	roots();
	mkbundle(sysroot, "Owner", "org.test.owner", "ownerd", "org.test.svc");
	/* a user bundle providing the SAME name */
	mkbundle(userroot, "Squatter", "org.test.squatter", "squatterd",
	    "org.test.svc");
	/* and one shadowing the system bundle's identity */
	mkbundle(userroot, "Shadow", "org.test.owner", "shadowd", "org.test.other");
	/* and a fine one */
	mkbundle(userroot, "Fine", "org.test.fine", "fined", "org.test.fine.svc");
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(2u, bundle_registry_count());	/* Owner + Fine */
	ATF_CHECK_EQ(2u, bundle_registry_quarantined());
	ATF_CHECK(bundle_registry_is_system(0));
	ATF_CHECK_STREQ("Owner.cap", capbundle_name(bundle_registry_get(0)));
	ATF_CHECK_STREQ("Fine.cap", capbundle_name(bundle_registry_get(1)));
	bundle_registry_teardown();
}

ATF_TC(registered_bundle_is_retained_when_unreadable);
ATF_TC_HEAD(registered_bundle_is_retained_when_unreadable, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(registered_bundle_is_retained_when_unreadable, tc)
{
	char p[PATH_MAX], q[PATH_MAX];

	roots();
	mkbundle(sysroot, "Sys", "org.test.sys", "sysd", "");
	mkbundle(userroot, "App", "org.test.app", "appd", "");
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(2u, bundle_registry_count());
	ATF_CHECK_EQ(0u, bundle_registry_quarantined());

	/* both caught half written: the unit manifest is momentarily gone */
	snprintf(p, sizeof(p), "%s/Sys.cap/Units/sysd.unit/Unit.ucl", sysroot);
	snprintf(q, sizeof(q), "%s/Sys.cap/Units/sysd.unit/Unit.ucl.x", sysroot);
	ATF_REQUIRE_EQ(0, rename(p, q));
	snprintf(p, sizeof(p), "%s/App.cap/Units/appd.unit/Unit.ucl", userroot);
	snprintf(q, sizeof(q), "%s/App.cap/Units/appd.unit/Unit.ucl.x", userroot);
	ATF_REQUIRE_EQ(0, rename(p, q));
	ATF_REQUIRE_EQ(0, bundle_registry_init());	/* rescan succeeds */
	ATF_CHECK_EQ(2u, bundle_registry_count());	/* both retained */
	ATF_CHECK_EQ(2u, bundle_registry_quarantined());	/* both retried */
	ATF_CHECK_STREQ("Sys.cap", capbundle_name(bundle_registry_get(0)));
	ATF_CHECK_STREQ("App.cap", capbundle_name(bundle_registry_get(1)));

	/* whole again: read from disk, nothing quarantined */
	snprintf(p, sizeof(p), "%s/Sys.cap/Units/sysd.unit/Unit.ucl", sysroot);
	snprintf(q, sizeof(q), "%s/Sys.cap/Units/sysd.unit/Unit.ucl.x", sysroot);
	ATF_REQUIRE_EQ(0, rename(q, p));
	snprintf(p, sizeof(p), "%s/App.cap/Units/appd.unit/Unit.ucl", userroot);
	snprintf(q, sizeof(q), "%s/App.cap/Units/appd.unit/Unit.ucl.x", userroot);
	ATF_REQUIRE_EQ(0, rename(q, p));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(2u, bundle_registry_count());
	ATF_CHECK_EQ(0u, bundle_registry_quarantined());

	/* a NEW half-written bundle is quarantined, not retained */
	mkbundle(userroot, "Half", "org.test.half", "halfd", "");
	snprintf(p, sizeof(p), "%s/Half.cap/Units/halfd.unit/Unit.ucl", userroot);
	ATF_REQUIRE_EQ(0, unlink(p));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(2u, bundle_registry_count());
	ATF_CHECK_EQ(1u, bundle_registry_quarantined());
	bundle_registry_teardown();
}

ATF_TC(root_spelling_does_not_unregister);
ATF_TC_HEAD(root_spelling_does_not_unregister, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(root_spelling_does_not_unregister, tc)
{
	char slashed[PATH_MAX], p[PATH_MAX], q[PATH_MAX];

	roots();
	mkbundle(sysroot, "Sys", "org.test.sys", "sysd", "");
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	/* the same root spelled with a trailing slash, bundle half written */
	snprintf(slashed, sizeof(slashed), "%s/", sysroot);
	switchboard_bundle_dir_system = slashed;
	snprintf(p, sizeof(p), "%s/Sys.cap/Units/sysd.unit/Unit.ucl", sysroot);
	snprintf(q, sizeof(q), "%s/Sys.cap/Units/sysd.unit/Unit.ucl.x", sysroot);
	ATF_REQUIRE_EQ(0, rename(p, q));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(1u, bundle_registry_count());	/* retained, not new */
	ATF_CHECK_EQ(1u, bundle_registry_quarantined());
	bundle_registry_teardown();
}

ATF_TC(vanished_system_root_retains);
ATF_TC_HEAD(vanished_system_root_retains, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(vanished_system_root_retains, tc)
{
	char gone[PATH_MAX];

	roots();
	mkbundle(sysroot, "Sys", "org.test.sys", "sysd", "");
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(1u, bundle_registry_count());
	snprintf(gone, sizeof(gone), "%s.gone", sysroot);
	ATF_REQUIRE_EQ(0, rename(sysroot, gone));
	ATF_CHECK_EQ(-1, bundle_registry_init());	/* retained */
	ATF_CHECK_EQ(1u, bundle_registry_count());
	ATF_REQUIRE_EQ(0, rename(gone, sysroot));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(1u, bundle_registry_count());
	bundle_registry_teardown();
}

/*
 * A per-user agent under <users>/<uid>/Agents, owned by that uid, loads and is
 * tagged with its owner -- the anchor the USER-class management gate keys on.
 * Runs as the build uid (== the "user"), so no root is needed: the agent's
 * files and its <uid>/Agents directory are owned by getuid().
 */
ATF_TC_WITHOUT_HEAD(per_user_agent_loads_with_owner);
ATF_TC_BODY(per_user_agent_loads_with_owner, tc)
{
	struct capbundle *bundle = NULL;
	char error[256];
	char cwd[PATH_MAX], usersdir[PATH_MAX], agentdir[PATH_MAX], p[PATH_MAX];
	uid_t me = getuid();

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* System/Apps absent -> skipped: only the per-user root is in play. */
	switchboard_bundle_dir_system = "/nonexistent/sb-sys";
	switchboard_bundle_dir_user = "/nonexistent/sb-apps";
	setenv("SWITCHBOARD_DISABLED_PATH", "/nonexistent/disabled", 1);

	snprintf(usersdir, sizeof(usersdir), "%s/Users", cwd);
	ATF_REQUIRE_EQ(0, mkdir(usersdir, 0755));
	snprintf(p, sizeof(p), "%s/%u", usersdir, (unsigned)me);
	ATF_REQUIRE_EQ(0, mkdir(p, 0755));
	snprintf(agentdir, sizeof(agentdir), "%s/%u/Agents", usersdir,
	    (unsigned)me);
	ATF_REQUIRE_EQ(0, mkdir(agentdir, 0700));
	switchboard_users_dir = usersdir;

	mkbundle(agentdir, "Agent", "org.test.agent", "agentd", "");

	/* A strict system must still permit an unsigned personal agent. */
	signatures_required = true;
	snprintf(p, sizeof(p), "%s/Agent.cap", agentdir);
	ATF_REQUIRE_EQ(-1, capbundle_open(p, &bundle, error, sizeof(error)));
	ATF_REQUIRE(bundle == NULL);
	ATF_REQUIRE_MSG(capbundle_open_trusted(p, NULL, false, &bundle,
	    error, sizeof(error)) == 0, "%s", error);
	capbundle_close(bundle);


	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_REQUIRE_EQ(1u, bundle_registry_count());
	ATF_CHECK_STREQ("Agent.cap", capbundle_name(bundle_registry_get(0)));
	ATF_CHECK_EQ(me, bundle_registry_owner_uid(0));
	bundle_registry_teardown();

	/* Optional signatures must not mean ignoring a malformed seal. */
	snprintf(p, sizeof(p), "%s/Agent.cap/Signature", agentdir);
	ATF_REQUIRE_EQ(0, mkdir(p, 0755));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(0u, bundle_registry_count());
	ATF_CHECK_EQ(1u, bundle_registry_quarantined());
	bundle_registry_teardown();

}

/*
 * A per-user agent with a group/world-writable file is untrusted and quarantined
 * (never loaded): a user's own tree must be as tamper-resistant as a system one.
 */
ATF_TC_WITHOUT_HEAD(per_user_agent_world_writable_rejected);
ATF_TC_BODY(per_user_agent_world_writable_rejected, tc)
{
	char cwd[PATH_MAX], usersdir[PATH_MAX], agentdir[PATH_MAX], p[PATH_MAX];
	uid_t me = getuid();

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	switchboard_bundle_dir_system = "/nonexistent/sb-sys";
	switchboard_bundle_dir_user = "/nonexistent/sb-apps";
	setenv("SWITCHBOARD_DISABLED_PATH", "/nonexistent/disabled", 1);

	snprintf(usersdir, sizeof(usersdir), "%s/Users", cwd);
	ATF_REQUIRE_EQ(0, mkdir(usersdir, 0755));
	snprintf(p, sizeof(p), "%s/%u", usersdir, (unsigned)me);
	ATF_REQUIRE_EQ(0, mkdir(p, 0755));
	snprintf(agentdir, sizeof(agentdir), "%s/%u/Agents", usersdir,
	    (unsigned)me);
	ATF_REQUIRE_EQ(0, mkdir(agentdir, 0700));
	switchboard_users_dir = usersdir;

	mkbundle(agentdir, "Bad", "org.test.bad", "badd", "");
	/* Make the unit manifest world-writable: trusted_tree must reject it. */
	snprintf(p, sizeof(p), "%s/Bad.cap/Units/badd.unit/Unit.ucl", agentdir);
	ATF_REQUIRE_EQ(0, chmod(p, 0666));

	ATF_REQUIRE_EQ(0, bundle_registry_init());	/* quarantine, not fatal */
	ATF_CHECK_EQ(0u, bundle_registry_count());
	bundle_registry_teardown();
}


ATF_TC_WITHOUT_HEAD(platform_attribute_scope);
ATF_TC_BODY(platform_attribute_scope, tc)
{
	const char *policies[] = {
	    "attributes=[\"org.test.protected\"];",
	    "holds=[\"org.test.protected\"];",
	    "capabilities { system=[\"sysctl\"]; }",
	    "capabilities { system=[\"sysctl\"]; isolate=[\"kern.hostname\"]; }",
	    "ambient=true; protocol=\"unix\";"
	};
	char path[PATH_MAX], unit[PATH_MAX], text[1024], error[256];
	struct capbundle *b;
	struct svc_manifest m;

	roots();
	mkbundle(userroot, "Local", "org.test.local", "local", "");
	snprintf(path, sizeof(path), "%s/Local.cap", userroot);
	snprintf(unit, sizeof(unit), "%s/Units/local.unit/Unit.ucl", path);
	for (unsigned i = 0; i < sizeof(policies)/sizeof(policies[0]); i++) {
		snprintf(text, sizeof(text), "program=\"local\"; "
		    "activation { boot=true; } %s\n", policies[i]);
		writef(unit, text, 0644);
		ATF_REQUIRE_MSG(capbundle_open_trusted(path, NULL, false, &b,
		    error, sizeof(error)) == 0, "%s", error);
		ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(
		    capbundle_service(b, 0), &m));
		ATF_CHECK(bundle_manifest_platform_allowed(&m, true, (uid_t)-1));
		/* Personal declarations still reach the existing confinement step. */
		ATF_CHECK(bundle_manifest_platform_allowed(&m, false, getuid()));
		ATF_CHECK_EQ(i == 4,
		    bundle_manifest_platform_allowed(&m, false, (uid_t)-1));
		capbundle_close(b);
	}
}


ATF_TC(local_platform_grants_quarantined);
ATF_TC_HEAD(local_platform_grants_quarantined, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(local_platform_grants_quarantined, tc)
{
	char path[PATH_MAX];
	roots();
	mkbundle(sysroot, "Base", "org.test.base", "base", "");
	snprintf(path, sizeof(path), "%s/Base.cap/Units/base.unit/Unit.ucl", sysroot);
	writef(path, "program=\"base\"; activation { boot=true; } "
	    "attributes=[\"org.test.protected\"];", 0644);
	mkbundle(userroot, "Bad", "org.test.bad", "bad", "");
	snprintf(path, sizeof(path), "%s/Bad.cap/Units/bad.unit/Unit.ucl", userroot);
	writef(path, "program=\"bad\"; activation { boot=true; } "
	    "attributes=[\"org.test.protected\"];", 0644);
	mkbundle(userroot, "Unix", "org.test.unix", "unix", "");
	snprintf(path, sizeof(path), "%s/Unix.cap/Units/unix.unit/Unit.ucl", userroot);
	writef(path, "program=\"unix\"; activation { boot=true; } "
	    "ambient=true; protocol=\"unix\";", 0644);
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(2u, bundle_registry_count());
	ATF_CHECK_EQ(1u, bundle_registry_quarantined());
	ATF_CHECK(bundle_registry_is_system(0));
	ATF_CHECK_STREQ("Base.cap", capbundle_name(bundle_registry_get(0)));
	ATF_CHECK_STREQ("Unix.cap", capbundle_name(bundle_registry_get(1)));
	bundle_registry_teardown();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, local_platform_grants_quarantined);
	ATF_TP_ADD_TC(tp, platform_attribute_scope);
	ATF_TP_ADD_TC(tp, user_conflicts_are_quarantined_not_fatal);
	ATF_TP_ADD_TC(tp, registered_bundle_is_retained_when_unreadable);
	ATF_TP_ADD_TC(tp, root_spelling_does_not_unregister);
	ATF_TP_ADD_TC(tp, vanished_system_root_retains);
	ATF_TP_ADD_TC(tp, per_user_agent_loads_with_owner);
	ATF_TP_ADD_TC(tp, per_user_agent_world_writable_rejected);
	return (atf_no_error());
}
