/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced management-class enforcement (§5).  Drives the absolute "core is
 * unmanageable" gate that every operator/runtime stop, restart, unload, and
 * disable path funnels through (sctl.c stop handler; reload.c Phase 1 teardown).
 * The gate is a pure function of the unit's class and needs no daemon event
 * loop, so synthetic svc_runtime units of each class exercise it directly.
 *
 * The principal-scoped system=root-only / user=owning-uid rules are NOT part of
 * this step; this test asserts the CORE refusal is absolute (independent of any
 * caller) and that system/user units are left permitted as they are today.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "serviced.h"
#include "management.h"

/* A minimal running unit of a given management class. */
static struct svc_runtime
unit_of_class(int management)
{
	struct svc_runtime svc;

	memset(&svc, 0, sizeof(svc));
	strlcpy(svc.manifest.label, "org.test.bundle/worker",
	    sizeof(svc.manifest.label));
	svc.manifest.management = management;
	svc.state = SVC_STATE_RUNNING;
	return (svc);
}

/* The verbs every operator/runtime management op reaches the gate under. */
static const char *const ops[] = { "stopped", "restarted", "unloaded",
    "disabled" };

ATF_TC_WITHOUT_HEAD(core_refuses_all_runtime_ops);
ATF_TC_BODY(core_refuses_all_runtime_ops, tc)
{
	struct svc_runtime svc = unit_of_class(SVC_MGMT_CORE);
	unsigned i;

	/*
	 * stop / restart / unload / disable are ALL refused for a core unit,
	 * and refused absolutely — no caller principal is consulted, so this
	 * stands in for "even root cannot".  A refusal means the caller (the
	 * sctl stop handler, the reload teardown loop) never invokes
	 * svc_graceful_stop(), so the unit stays running.
	 */
	for (i = 0; i < nitems(ops); i++)
		ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&svc, ops[i]),
		    "core op '%s' was not refused", ops[i]);

	/* State is untouched by the gate: the unit is still running. */
	ATF_CHECK_EQ(SVC_STATE_RUNNING, svc.state);
}

ATF_TC_WITHOUT_HEAD(system_allows_runtime_ops);
ATF_TC_BODY(system_allows_runtime_ops, tc)
{
	struct svc_runtime svc = unit_of_class(SVC_MGMT_SYSTEM);
	unsigned i;

	/* system is today's default; the gate permits (transport still gates). */
	for (i = 0; i < nitems(ops); i++)
		ATF_CHECK_EQ_MSG(0, svc_management_check_op(&svc, ops[i]),
		    "system op '%s' was refused", ops[i]);
}

ATF_TC_WITHOUT_HEAD(user_allows_runtime_ops);
ATF_TC_BODY(user_allows_runtime_ops, tc)
{
	struct svc_runtime svc = unit_of_class(SVC_MGMT_USER);
	unsigned i;

	for (i = 0; i < nitems(ops); i++)
		ATF_CHECK_EQ_MSG(0, svc_management_check_op(&svc, ops[i]),
		    "user op '%s' was refused", ops[i]);
}

ATF_TC_WITHOUT_HEAD(default_zero_init_is_system);
ATF_TC_BODY(default_zero_init_is_system, tc)
{
	struct svc_runtime svc;

	/* A calloc/memset unit (management == 0) must behave as system. */
	memset(&svc, 0, sizeof(svc));
	strlcpy(svc.manifest.label, "org.test.bundle/zero",
	    sizeof(svc.manifest.label));
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, svc.manifest.management);
	ATF_CHECK_EQ(0, svc_management_check_op(&svc, "stopped"));
}

ATF_TC_WITHOUT_HEAD(class_gate_matches_op_wrapper);
ATF_TC_BODY(class_gate_matches_op_wrapper, tc)
{

	/* The class-level entry point mirrors the runtime wrapper. */
	ATF_CHECK_EQ(EPERM, svc_management_check_class(SVC_MGMT_CORE,
	    "org.test/core", "stopped"));
	ATF_CHECK_EQ(0, svc_management_check_class(SVC_MGMT_SYSTEM,
	    "org.test/system", "stopped"));
	ATF_CHECK_EQ(0, svc_management_check_class(SVC_MGMT_USER,
	    "org.test/user", "stopped"));
}

ATF_TC_WITHOUT_HEAD(null_unit_is_permitted);
ATF_TC_BODY(null_unit_is_permitted, tc)
{

	/* A NULL unit must not fault and must not spuriously refuse. */
	ATF_CHECK_EQ(0, svc_management_check_op(NULL, "stopped"));
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
 * Lifecycle guarantee (§5): reload-on-manifest-change must still act on a core
 * unit — only operator/runtime stop/unload is refused.  reload.c Phase 2
 * (manifest changed -> restart in place) deliberately does NOT call the gate,
 * while Phase 1 (removed/unloaded) does.  This test pins the property the gate
 * relies on: it is a pure function of class, so any lifecycle code path that
 * never consults it is wholly unaffected by a unit being core.
 */
ATF_TC_WITHOUT_HEAD(gate_is_pure_class_function);
ATF_TC_BODY(gate_is_pure_class_function, tc)
{
	struct svc_runtime a = unit_of_class(SVC_MGMT_CORE);
	struct svc_runtime b = unit_of_class(SVC_MGMT_CORE);

	/* Differing runtime state must not change the decision. */
	a.state = SVC_STATE_RUNNING;
	b.state = SVC_STATE_STARTING;
	ATF_CHECK_EQ(svc_management_check_op(&a, "unloaded"),
	    svc_management_check_op(&b, "unloaded"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, core_refuses_all_runtime_ops);
	ATF_TP_ADD_TC(tp, system_allows_runtime_ops);
	ATF_TP_ADD_TC(tp, user_allows_runtime_ops);
	ATF_TP_ADD_TC(tp, default_zero_init_is_system);
	ATF_TP_ADD_TC(tp, class_gate_matches_op_wrapper);
	ATF_TP_ADD_TC(tp, null_unit_is_permitted);
	ATF_TP_ADD_TC(tp, management_names);
	ATF_TP_ADD_TC(tp, gate_is_pure_class_function);

	return (atf_no_error());
}
