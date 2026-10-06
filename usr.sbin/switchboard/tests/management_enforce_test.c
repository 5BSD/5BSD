/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard management-class enforcement (§5).  Drives the gate that every
 * runtime stop/start/restart/unload/disable path funnels through (sctl.c
 * start/stop handlers; reload.c teardown).  The gate is a pure function of the
 * unit's class, the caller's uid, whether the caller holds operator authority,
 * and (for user agents) the unit's owning uid, so synthetic svc_runtime units
 * exercise it directly with no daemon event loop.
 *
 * The three classes:
 *   CORE   -- refused for EVERYONE, absolutely (escalation-proof: no uid, no
 *             operator bit gets past it).
 *   SYSTEM -- permitted only for an operator.
 *   USER   -- permitted for an operator OR the owning uid itself.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "switchboard.h"
#include "management.h"

#define	OWNER_UID	1001
#define	STRANGER_UID	1002

/*
 * A minimal unit of a given management class, owned by `owner`
 * ((uid_t)-1 = none).  Filled in place: struct svc_runtime is well over a
 * hundred kilobytes, so returning one by value puts two copies of it on the
 * stack for every fixture and makes what the caller is actually inspecting
 * hard to follow.
 */
static void
unit_of(struct svc_runtime *svc, int management, uid_t owner)
{

	memset(svc, 0, sizeof(*svc));
	strlcpy(svc->manifest.label, "org.test.bundle/worker",
	    sizeof(svc->manifest.label));
	svc->manifest.management = management;
	svc->owner_uid = owner;
	svc->state = SVC_STATE_RUNNING;
}

/* The verbs every runtime management op reaches the gate under. */
static const char *const ops[] = { "stopped", "started", "restarted",
    "unloaded", "disabled", "changed at runtime" };

ATF_TC_WITHOUT_HEAD(core_refuses_everyone);
ATF_TC_BODY(core_refuses_everyone, tc)
{
	struct svc_runtime svc;
	unsigned i;

	unit_of(&svc, SVC_MGMT_CORE, (uid_t)-1);

	/*
	 * Prove the fixture before trusting what the gate says about it: if the
	 * class did not survive being set, every check below would be testing
	 * the default class instead and would fail for the wrong reason.
	 */
	ATF_REQUIRE_EQ_MSG(SVC_MGMT_CORE, svc.manifest.management,
	    "fixture did not keep the management class: got %d",
	    svc.manifest.management);

	/*
	 * A core unit is refused for EVERY caller and EVERY op -- an operator,
	 * uid 0, the owning uid, a stranger.  This is the escalation-proof SIP
	 * tier: no privilege a caller could acquire satisfies it.
	 */
	for (i = 0; i < nitems(ops); i++) {
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&svc, ops[i],
		    0, true), "core op '%s' allowed for operator", ops[i]);
		/*
		 * The class gate reached directly as well as through the
		 * wrapper.  The two disagreeing means the wrapper is reading
		 * the unit's class from somewhere other than where the caller
		 * wrote it, which is how a stale shared object shows up.
		 */
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_class(
		    SVC_MGMT_CORE, "org.test/core", ops[i], 0, true,
		    (uid_t)-1), "core op '%s' allowed by the class gate",
		    ops[i]);
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&svc, ops[i],
		    0, false), "core op '%s' allowed for uid 0", ops[i]);
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&svc, ops[i],
		    OWNER_UID, false), "core op '%s' allowed for a uid", ops[i]);
	}
	ATF_CHECK_EQ(SVC_STATE_RUNNING, svc.state);
}

ATF_TC_WITHOUT_HEAD(system_requires_operator);
ATF_TC_BODY(system_requires_operator, tc)
{
	struct svc_runtime svc;

	unit_of(&svc, SVC_MGMT_SYSTEM, (uid_t)-1);
	unsigned i;

	for (i = 0; i < nitems(ops); i++) {
		/* An operator may manage a system unit. */
		ATF_CHECK_EQ_MSG(0, svc_management_check_op(&svc, ops[i],
		    (uid_t)-1, true), "system op '%s' refused for operator",
		    ops[i]);
		/* A non-operator may NOT -- not even uid 0 by uid alone. */
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&svc, ops[i],
		    0, false), "system op '%s' allowed for uid 0", ops[i]);
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&svc, ops[i],
		    OWNER_UID, false), "system op '%s' allowed for a uid",
		    ops[i]);
	}
}

ATF_TC_WITHOUT_HEAD(user_owner_or_operator);
ATF_TC_BODY(user_owner_or_operator, tc)
{
	struct svc_runtime svc;
	unsigned i;

	unit_of(&svc, SVC_MGMT_USER, OWNER_UID);

	for (i = 0; i < nitems(ops); i++) {
		/* The owning uid manages its own agent (self-service). */
		ATF_CHECK_EQ_MSG(0, svc_management_check_op(&svc, ops[i],
		    OWNER_UID, false), "user op '%s' refused for owner", ops[i]);
		/* An operator may too. */
		ATF_CHECK_EQ_MSG(0, svc_management_check_op(&svc, ops[i],
		    (uid_t)-1, true), "user op '%s' refused for operator",
		    ops[i]);
		/* A different, non-operator uid may NOT. */
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&svc, ops[i],
		    STRANGER_UID, false), "user op '%s' allowed for a stranger",
		    ops[i]);
	}
}

ATF_TC_WITHOUT_HEAD(user_unowned_needs_operator);
ATF_TC_BODY(user_unowned_needs_operator, tc)
{
	/* A user-class unit with no recorded owner ((uid_t)-1) is manageable
	 * only by an operator: an unknown caller uid must never match -1. */
	struct svc_runtime svc;

	unit_of(&svc, SVC_MGMT_USER, (uid_t)-1);

	ATF_CHECK_EQ(EPERM, svc_management_check_op(&svc, "stopped",
	    (uid_t)-1, false));
	ATF_CHECK_EQ(EPERM, svc_management_check_op(&svc, "stopped",
	    OWNER_UID, false));
	ATF_CHECK_EQ(0, svc_management_check_op(&svc, "stopped",
	    (uid_t)-1, true));
}

ATF_TC_WITHOUT_HEAD(default_zero_init_is_system);
ATF_TC_BODY(default_zero_init_is_system, tc)
{
	struct svc_runtime svc;

	/* A calloc/memset unit (management == 0) behaves as system: operator
	 * required, a bare uid refused. */
	memset(&svc, 0, sizeof(svc));
	strlcpy(svc.manifest.label, "org.test.bundle/zero",
	    sizeof(svc.manifest.label));
	svc.owner_uid = (uid_t)-1;
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, svc.manifest.management);
	ATF_CHECK_EQ(0, svc_management_check_op(&svc, "stopped", (uid_t)-1, true));
	ATF_CHECK_EQ(EPERM, svc_management_check_op(&svc, "stopped", 0, false));
}

ATF_TC_WITHOUT_HEAD(class_gate_matches_op_wrapper);
ATF_TC_BODY(class_gate_matches_op_wrapper, tc)
{

	/* Core: refused regardless of caller. */
	ATF_CHECK_EQ(EPERM, svc_management_check_class(SVC_MGMT_CORE,
	    "org.test/core", "stopped", 0, true, (uid_t)-1));
	/* System: operator only. */
	ATF_CHECK_EQ(0, svc_management_check_class(SVC_MGMT_SYSTEM,
	    "org.test/system", "stopped", (uid_t)-1, true, (uid_t)-1));
	ATF_CHECK_EQ(EPERM, svc_management_check_class(SVC_MGMT_SYSTEM,
	    "org.test/system", "stopped", OWNER_UID, false, (uid_t)-1));
	/* User: owner or operator. */
	ATF_CHECK_EQ(0, svc_management_check_class(SVC_MGMT_USER,
	    "org.test/user", "stopped", OWNER_UID, false, OWNER_UID));
	ATF_CHECK_EQ(EPERM, svc_management_check_class(SVC_MGMT_USER,
	    "org.test/user", "stopped", STRANGER_UID, false, OWNER_UID));
}

ATF_TC_WITHOUT_HEAD(null_unit_is_permitted);
ATF_TC_BODY(null_unit_is_permitted, tc)
{

	/* A NULL unit must not fault and must not spuriously refuse. */
	ATF_CHECK_EQ(0, svc_management_check_op(NULL, "stopped", 0, false));
}

ATF_TC_WITHOUT_HEAD(management_names);
ATF_TC_BODY(management_names, tc)
{

	ATF_CHECK_STREQ("core", svc_management_name(SVC_MGMT_CORE));
	ATF_CHECK_STREQ("system", svc_management_name(SVC_MGMT_SYSTEM));
	ATF_CHECK_STREQ("user", svc_management_name(SVC_MGMT_USER));
	ATF_CHECK_STREQ("unknown", svc_management_name(99));
}

/*
 * Core is a pure function of class: differing runtime state never makes it
 * replaceable, for any caller.
 */
ATF_TC_WITHOUT_HEAD(core_gate_is_pure_class_function);
ATF_TC_BODY(core_gate_is_pure_class_function, tc)
{
	struct svc_runtime a, b;

	unit_of(&a, SVC_MGMT_CORE, (uid_t)-1);
	unit_of(&b, SVC_MGMT_CORE, (uid_t)-1);

	a.state = SVC_STATE_RUNNING;
	b.state = SVC_STATE_STARTING;
	ATF_CHECK_EQ(svc_management_check_op(&a, "unloaded", 0, true),
	    svc_management_check_op(&b, "unloaded", 0, true));
}

ATF_TC_WITHOUT_HEAD(band_boost_needs_system);
ATF_TC_BODY(band_boost_needs_system, tc)
{

	/* STANDARD and BACKGROUND (throttle down) pass through for any unit. */
	ATF_CHECK_EQ(SVC_BAND_STANDARD, svc_effective_band(SVC_BAND_STANDARD, false));
	ATF_CHECK_EQ(SVC_BAND_STANDARD, svc_effective_band(SVC_BAND_STANDARD, true));
	ATF_CHECK_EQ(SVC_BAND_BACKGROUND,
	    svc_effective_band(SVC_BAND_BACKGROUND, false));
	ATF_CHECK_EQ(SVC_BAND_BACKGROUND,
	    svc_effective_band(SVC_BAND_BACKGROUND, true));
	/* The INTERACTIVE boost is a privilege: a system bundle keeps it... */
	ATF_CHECK_EQ(SVC_BAND_INTERACTIVE,
	    svc_effective_band(SVC_BAND_INTERACTIVE, true));
	/* ...but a non-system unit (app or user agent) is clamped to STANDARD. */
	ATF_CHECK_EQ(SVC_BAND_STANDARD,
	    svc_effective_band(SVC_BAND_INTERACTIVE, false));
}

ATF_TC_WITHOUT_HEAD(user_manifest_cannot_grant_attributes);
ATF_TC_BODY(user_manifest_cannot_grant_attributes, tc)
{
	struct svc_runtime svc;
	struct svc_manifest trusted;

	(void)tc;
	unit_of(&svc, SVC_MGMT_CORE, OWNER_UID);
	svc.manifest.domain = SVC_MANIFEST_DOMAIN_SYSTEM;
	svc.manifest.ambient = true;
	svc.manifest.user_resolvable = true;
	svc.manifest.cap_system = UINT32_MAX;
	svc.manifest.nactivation_sockets = 1;
	svc.manifest.n_sysctl_isolate = 1;
	svc.manifest.nanointments = 2;
	strlcpy(svc.manifest.anointments[0], "system.switchboard.admin",
	    sizeof(svc.manifest.anointments[0]));
	strlcpy(svc.manifest.anointments[1], "system.trace.client",
	    sizeof(svc.manifest.anointments[1]));
	trusted = svc.manifest;
	svc_user_manifest_confine(&svc);
	ATF_CHECK_EQ(SVC_MGMT_USER, svc.manifest.management);
	ATF_CHECK_EQ(SVC_MANIFEST_DOMAIN_USER, svc.manifest.domain);
	ATF_CHECK(!svc.manifest.ambient);
	ATF_CHECK(!svc.manifest.user_resolvable);
	ATF_CHECK_EQ(0, svc.manifest.cap_system);
	ATF_CHECK_EQ(0, svc.manifest.nactivation_sockets);
	ATF_CHECK_EQ(0, svc.manifest.n_sysctl_isolate);
	ATF_CHECK_EQ(0, svc.manifest.nanointments);
	ATF_CHECK_STREQ("", svc.manifest.anointments[0]);
	ATF_CHECK_STREQ("", svc.manifest.anointments[1]);
	/* Reloading an attacker-controlled declaration must clear it again. */
	svc.manifest = trusted;
	svc_user_manifest_confine(&svc);
	ATF_CHECK_EQ(0, svc.manifest.nanointments);
	/* Trusted installation policy remains effective. */
	svc.owner_uid = (uid_t)-1;
	svc.manifest = trusted;
	svc_user_manifest_confine(&svc);
	ATF_CHECK_EQ(0, memcmp(&trusted, &svc.manifest, sizeof(trusted)));
}

ATF_TC_WITHOUT_HEAD(user_manifest_credentials_follow_owner);
ATF_TC_BODY(user_manifest_credentials_follow_owner, tc)
{
	struct svc_runtime svc;
	struct passwd *pw;
	char expected[64];

	(void)tc;
	pw = getpwuid(getuid());
	ATF_REQUIRE(pw != NULL);
	strlcpy(expected, pw->pw_name, sizeof(expected));
	unit_of(&svc, SVC_MGMT_USER, getuid());
	strlcpy(svc.manifest.user, "root", sizeof(svc.manifest.user));
	strlcpy(svc.manifest.group, "wheel", sizeof(svc.manifest.group));
	ATF_REQUIRE_EQ(0, svc_user_manifest_credentials(&svc));
	ATF_CHECK_STREQ(expected, svc.manifest.user);
	ATF_CHECK_STREQ("", svc.manifest.group);
	/* Trusted policy can intentionally select a different account. */
	svc.owner_uid = (uid_t)-1;
	strlcpy(svc.manifest.user, "root", sizeof(svc.manifest.user));
	strlcpy(svc.manifest.group, "wheel", sizeof(svc.manifest.group));
	ATF_REQUIRE_EQ(0, svc_user_manifest_credentials(&svc));
	ATF_CHECK_STREQ("root", svc.manifest.user);
	ATF_CHECK_STREQ("wheel", svc.manifest.group);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, user_manifest_cannot_grant_attributes);
	ATF_TP_ADD_TC(tp, user_manifest_credentials_follow_owner);

	ATF_TP_ADD_TC(tp, band_boost_needs_system);
	ATF_TP_ADD_TC(tp, core_refuses_everyone);
	ATF_TP_ADD_TC(tp, system_requires_operator);
	ATF_TP_ADD_TC(tp, user_owner_or_operator);
	ATF_TP_ADD_TC(tp, user_unowned_needs_operator);
	ATF_TP_ADD_TC(tp, default_zero_init_is_system);
	ATF_TP_ADD_TC(tp, class_gate_matches_op_wrapper);
	ATF_TP_ADD_TC(tp, null_unit_is_permitted);
	ATF_TP_ADD_TC(tp, management_names);
	ATF_TP_ADD_TC(tp, core_gate_is_pure_class_function);

	return (atf_no_error());
}
