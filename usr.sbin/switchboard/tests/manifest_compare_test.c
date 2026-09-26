/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdio.h>
#include <string.h>

#include "manifest_compare.h"

static struct svc_manifest
sample_manifest(void)
{
	struct svc_manifest m;

	memset(&m, 0, sizeof(m));
	strlcpy(m.label, "org.test.bundle/program", sizeof(m.label));
	strlcpy(m.program, "/Capabilities/Test.cap/bin/program",
	    sizeof(m.program));
	strlcpy(m.user, "capability", sizeof(m.user));
	strlcpy(m.group, "capability", sizeof(m.group));
	strlcpy(m.arguments[0], "argument", sizeof(m.arguments[0]));
	m.narguments = 1;
	strlcpy(m.environment[0], "KEY=value", sizeof(m.environment[0]));
	m.nenvironment = 1;
	strlcpy(m.provides[0], "org.test.endpoint", sizeof(m.provides[0]));
	m.nprovides = 1;
	m.cap_system = 1;
	m.restart = 1;
	m.stop_timeout = 5;
	m.max_failures = 10;
	return (m);
}

#define CHECK_CHANGE(statement) do { \
	a = sample_manifest(); \
	b = a; \
	statement; \
	ATF_CHECK(!switchboard_manifest_equal(&a, &b)); \
} while (0)

ATF_TC_WITHOUT_HEAD(equal_and_unused_tail);
ATF_TC_BODY(equal_and_unused_tail, tc)
{
	struct svc_manifest a, b;

	a = sample_manifest();
	b = a;
	ATF_REQUIRE(switchboard_manifest_equal(&a, &b));
	strlcpy(b.arguments[1], "unused", sizeof(b.arguments[1]));
	ATF_CHECK(switchboard_manifest_equal(&a, &b));
}

ATF_TC_WITHOUT_HEAD(identity_and_execution_changes);
ATF_TC_BODY(identity_and_execution_changes, tc)
{
	struct svc_manifest a, b;

	CHECK_CHANGE(b.label[0] = 'x');
	CHECK_CHANGE(b.program[0] = 'x');
	CHECK_CHANGE(b.user[0] = 'x');
	CHECK_CHANGE(b.group[0] = 'x');
	CHECK_CHANGE(b.arguments[0][0] = 'x');
	CHECK_CHANGE(b.environment[0][0] = 'x');
	CHECK_CHANGE(b.restart++);
	CHECK_CHANGE(b.stop_timeout++);
	CHECK_CHANGE(b.max_failures++);
	/* A changed liveness-watchdog interval must force a reload. */
	CHECK_CHANGE(b.watchdog_interval++);
	CHECK_CHANGE(b.provides[0][0] = 'x');
}

ATF_TC_WITHOUT_HEAD(capsule_changes);
ATF_TC_BODY(capsule_changes, tc)
{
	struct svc_manifest a, b;

	CHECK_CHANGE(b.cap_system++);
	CHECK_CHANGE(b.protect_flags++);
	/* Toggling the mint-authority role must force a reload (§6). */
	CHECK_CHANGE(b.mint_authority = !b.mint_authority);
}

/*
 * Per-OID sysctl isolation set (Phase 2): a change to the isolate list — its
 * count OR any name — must be detected so reload restarts the provider with a
 * fresh scoped SYSCTL token.  Equal lists must still compare equal.
 */
ATF_TC_WITHOUT_HEAD(sysctl_isolate_changes);
ATF_TC_BODY(sysctl_isolate_changes, tc)
{
	struct svc_manifest a, b;

	/* Count change. */
	CHECK_CHANGE(b.n_sysctl_isolate++);

	/* Name change with equal count. */
	a = sample_manifest();
	a.n_sysctl_isolate = 1;
	strlcpy(a.sysctl_isolate[0], "kern.maxfiles",
	    sizeof(a.sysctl_isolate[0]));
	b = a;
	strlcpy(b.sysctl_isolate[0], "vm.overcommit",
	    sizeof(b.sysctl_isolate[0]));
	ATF_CHECK(!switchboard_manifest_equal(&a, &b));

	/* Identical non-empty lists compare equal. */
	b = a;
	ATF_CHECK(switchboard_manifest_equal(&a, &b));
}

/*
 * IPC anointments (docs/book/src/plane/anointments.md): per-endpoint `requires`
 * and the unit's own `anointments` are reach policy, so any change -- a
 * name, a count, or (DOCUMENTED) merely the order of the same names -- must
 * compare unequal so reload restarts the unit with the new policy.  Unused
 * trailing slots past the counts are irrelevant, and the comparison covers
 * every populated endpoint and every populated requires slot, including the
 * last of each (SWITCHBOARD_MAX_PROVIDES - 1, SWITCHBOARD_MAX_REQUIRES - 1).
 */
static struct svc_manifest
anointed_manifest(void)
{
	struct svc_manifest m;
	unsigned i, j;

	m = sample_manifest();
	/* Every provides slot populated; endpoint i requires i names. */
	for (i = 0; i < SWITCHBOARD_MAX_PROVIDES; i++) {
		snprintf(m.provides[i], sizeof(m.provides[i]),
		    "org.test.Endpoint%u", i);
		m.nrequires[i] = i;
		for (j = 0; j < i; j++)
			snprintf(m.requires[i][j], sizeof(m.requires[i][j]),
			    "org.test.req.%u.%u", i, j);
	}
	m.nprovides = SWITCHBOARD_MAX_PROVIDES;
	for (i = 0; i < 3; i++)
		snprintf(m.anointments[i], sizeof(m.anointments[i]),
		    "org.test.held.%u", i);
	m.nanointments = 3;
	return (m);
}

#define CHECK_ANOINT_CHANGE(statement) do { \
	a = anointed_manifest(); \
	b = a; \
	statement; \
	ATF_CHECK_MSG(!switchboard_manifest_equal(&a, &b), "%s", #statement); \
	ATF_CHECK_MSG(!switchboard_manifest_equal(&b, &a), "%s (reversed)", \
	    #statement); \
} while (0)

ATF_TC_WITHOUT_HEAD(anointment_policy_changes);
ATF_TC_BODY(anointment_policy_changes, tc)
{
	struct svc_manifest a, b;
	char tmp[SWITCHBOARD_LABEL_MAX];

	/* Identical, non-trivial policy: equal both ways. */
	a = anointed_manifest();
	b = a;
	ATF_REQUIRE(switchboard_manifest_equal(&a, &b));
	ATF_REQUIRE(switchboard_manifest_equal(&b, &a));

	/* One requires name differs (first endpoint that has one). */
	CHECK_ANOINT_CHANGE(b.requires[1][0][0] = 'x');
	/* A single-character, single-byte change at the tail of a name. */
	CHECK_ANOINT_CHANGE(strlcat(b.requires[1][0], "x",
	    sizeof(b.requires[1][0])));
	/* Case only. */
	CHECK_ANOINT_CHANGE(b.requires[1][0][0] = 'O');

	/* Same requires names, different order: NOT equal (documented). */
	CHECK_ANOINT_CHANGE(
	    strlcpy(tmp, b.requires[2][0], sizeof(tmp));
	    strlcpy(b.requires[2][0], b.requires[2][1],
	        sizeof(b.requires[2][0]));
	    strlcpy(b.requires[2][1], tmp, sizeof(b.requires[2][1])));

	/* nrequires differs with the same names in place (an endpoint
	 * opened, or gated, without editing the slots). */
	CHECK_ANOINT_CHANGE(b.nrequires[1] = 0);
	CHECK_ANOINT_CHANGE(b.nrequires[0] = 1);
	CHECK_ANOINT_CHANGE(b.nrequires[7]++);

	/* The 8th endpoint (index 7): its name, its 1st and its 7th (last)
	 * requires slot. */
	CHECK_ANOINT_CHANGE(b.provides[7][0] = 'x');
	CHECK_ANOINT_CHANGE(b.requires[7][0][0] = 'x');
	CHECK_ANOINT_CHANGE(b.requires[7][6][0] = 'x');
	/* ...and the 8th requires slot of the 8th endpoint once it exists. */
	a = anointed_manifest();
	a.nrequires[7] = SWITCHBOARD_MAX_REQUIRES;
	strlcpy(a.requires[7][7], "org.test.req.7.7", sizeof(a.requires[7][7]));
	b = a;
	ATF_REQUIRE(switchboard_manifest_equal(&a, &b));
	b.requires[7][7][0] = 'x';
	ATF_CHECK(!switchboard_manifest_equal(&a, &b));

	/* The unit's own anointments: count, name, order. */
	CHECK_ANOINT_CHANGE(b.nanointments++);
	CHECK_ANOINT_CHANGE(b.nanointments--);
	CHECK_ANOINT_CHANGE(b.nanointments = 0);
	CHECK_ANOINT_CHANGE(b.anointments[0][0] = 'x');
	CHECK_ANOINT_CHANGE(b.anointments[2][0] = 'x');
	CHECK_ANOINT_CHANGE(
	    strlcpy(tmp, b.anointments[0], sizeof(tmp));
	    strlcpy(b.anointments[0], b.anointments[1],
	        sizeof(b.anointments[0]));
	    strlcpy(b.anointments[1], tmp, sizeof(b.anointments[1])));

	/* Unused slots past the counts do not matter. */
	a = anointed_manifest();
	b = a;
	strlcpy(b.anointments[3], "org.test.unused", sizeof(b.anointments[3]));
	strlcpy(b.requires[0][0], "org.test.unused", sizeof(b.requires[0][0]));
	strlcpy(b.requires[1][1], "org.test.unused", sizeof(b.requires[1][1]));
	strlcpy(b.requires[7][7], "org.test.unused", sizeof(b.requires[7][7]));
	ATF_CHECK(switchboard_manifest_equal(&a, &b));
	ATF_CHECK(switchboard_manifest_equal(&b, &a));
	/* A slot past nprovides, requires and all, is unused too. */
	a.nprovides = 7;
	b = a;
	strlcpy(b.provides[7], "org.test.gone", sizeof(b.provides[7]));
	b.nrequires[7] = 3;
	strlcpy(b.requires[7][0], "org.test.gone", sizeof(b.requires[7][0]));
	ATF_CHECK(switchboard_manifest_equal(&a, &b));

	/* No anointment policy at all on both sides: still equal. */
	a = sample_manifest();
	b = a;
	ATF_CHECK(switchboard_manifest_equal(&a, &b));
	/* ...and gating the one endpoint is a change. */
	b.nrequires[0] = 1;
	strlcpy(b.requires[0][0], "org.test.req", sizeof(b.requires[0][0]));
	ATF_CHECK(!switchboard_manifest_equal(&a, &b));
	/* ...as is giving the unit an anointment. */
	b = a;
	b.nanointments = 1;
	strlcpy(b.anointments[0], "org.test.held", sizeof(b.anointments[0]));
	ATF_CHECK(!switchboard_manifest_equal(&a, &b));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, equal_and_unused_tail);
	ATF_TP_ADD_TC(tp, identity_and_execution_changes);
	ATF_TP_ADD_TC(tp, capsule_changes);
	ATF_TP_ADD_TC(tp, sysctl_isolate_changes);
	ATF_TP_ADD_TC(tp, anointment_policy_changes);
	return (atf_no_error());
}
