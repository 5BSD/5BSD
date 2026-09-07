/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced control-plane authorization gate (P3, sctl.c / sctl_gate.h).
 *
 * Negative coverage for the capability control channel: every STATE-CHANGING
 * control op (reload, start, stop, reclaim) requires the ADMIN right held on
 * the caller's grant; a non-admin caller is refused with EPERM, while the
 * read-only STATUS/SERVICES ops stay open to any control grant.  These are the
 * two pure predicates sctl_cap_request()/sctl_execute_op() funnel through, so
 * they exercise the gate directly with no daemon event loop.
 *
 * A SECOND, independent gate is asserted too: the management-class rule that a
 * CORE unit is unstoppable even for an ADMIN caller (management.c).  Admin
 * clears the rights door; the class check then refuses the stop regardless.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "serviced.h"
#include "management.h"
#include "sctl_gate.h"

/*
 * The state-changing ops and the read-only ops, named for the assertion
 * messages so a regression points straight at the offending opcode.
 */
static const struct { uint32_t op; const char *name; } mutating_ops[] = {
	{ SCTL_OP_RELOAD,	"RELOAD" },
	{ SCTL_OP_START_SVC,	"START" },
	{ SCTL_OP_STOP_SVC,	"STOP" },
	{ SCTL_OP_RECLAIM,	"RECLAIM" },
};
static const struct { uint32_t op; const char *name; } readonly_ops[] = {
	{ SCTL_OP_STATUS,	"STATUS" },
	{ SCTL_OP_SERVICES,	"SERVICES" },
};

/*
 * Gap 1 — a non-admin caller is denied every state-changing control op.  The
 * runtime derives is_admin from the held rights and, for these ops, refuses
 * with EPERM when it is false.  Modelled here as: the op requires admin AND
 * the caller is not admin => the gate would deny.
 */
ATF_TC_WITHOUT_HEAD(nonadmin_denied_all_mutating_ops);
ATF_TC_BODY(nonadmin_denied_all_mutating_ops, tc)
{
	/* A caller holding rights but NOT the ADMIN bit is non-admin. */
	uint64_t nonadmin_rights = SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN;
	bool is_admin = sctl_rights_is_admin(nonadmin_rights);
	unsigned i;

	ATF_CHECK_MSG(!is_admin,
	    "rights without the ADMIN bit must not derive admin authority");
	for (i = 0; i < nitems(mutating_ops); i++) {
		bool denied = sctl_op_requires_admin(mutating_ops[i].op) &&
		    !is_admin;

		ATF_CHECK_MSG(sctl_op_requires_admin(mutating_ops[i].op),
		    "op %s must require admin", mutating_ops[i].name);
		ATF_CHECK_MSG(denied,
		    "non-admin caller must be denied op %s (EPERM)",
		    mutating_ops[i].name);
	}
}

/*
 * An ADMIN caller passes the rights gate for every state-changing op.  This
 * pins the positive half so the denial above is not vacuously true.
 */
ATF_TC_WITHOUT_HEAD(admin_passes_all_mutating_ops);
ATF_TC_BODY(admin_passes_all_mutating_ops, tc)
{
	bool is_admin = sctl_rights_is_admin(SVC_RIGHTS_ADMIN);
	unsigned i;

	ATF_CHECK_MSG(is_admin, "the ADMIN bit must derive admin authority");
	for (i = 0; i < nitems(mutating_ops); i++)
		ATF_CHECK_MSG(!(sctl_op_requires_admin(mutating_ops[i].op) &&
		    !is_admin),
		    "admin caller must pass the rights gate for op %s",
		    mutating_ops[i].name);
}

/*
 * Read-only ops are open to any control grant: they never require admin, so a
 * non-admin caller is NOT denied STATUS/SERVICES.
 */
ATF_TC_WITHOUT_HEAD(readonly_ops_open_to_nonadmin);
ATF_TC_BODY(readonly_ops_open_to_nonadmin, tc)
{
	bool is_admin = false;
	unsigned i;

	for (i = 0; i < nitems(readonly_ops); i++) {
		ATF_CHECK_MSG(!sctl_op_requires_admin(readonly_ops[i].op),
		    "read-only op %s must not require admin",
		    readonly_ops[i].name);
		ATF_CHECK_MSG(!(sctl_op_requires_admin(readonly_ops[i].op) &&
		    !is_admin),
		    "non-admin caller must be permitted read-only op %s",
		    readonly_ops[i].name);
	}
}

/*
 * Fail-closed: an unrecognized opcode is treated as privileged (requires
 * admin), so an unprivileged caller can never reach an unknown op.
 */
ATF_TC_WITHOUT_HEAD(unknown_op_requires_admin);
ATF_TC_BODY(unknown_op_requires_admin, tc)
{

	ATF_CHECK_MSG(sctl_op_requires_admin(0),
	    "opcode 0 must be treated as privileged");
	ATF_CHECK_MSG(sctl_op_requires_admin(0xffffffffu),
	    "an unknown opcode must be treated as privileged");
	/* Opcode 6 was retired (SCTL_OP_PROVISION_SESSION): still deny. */
	ATF_CHECK_MSG(sctl_op_requires_admin(6),
	    "a retired opcode must not become an open read-only op");
}

/*
 * Rights derivation authenticity: authority is the held SVC_RIGHTS_ADMIN bit,
 * not any other right and not a uid.
 */
ATF_TC_WITHOUT_HEAD(rights_derivation_is_admin_bit);
ATF_TC_BODY(rights_derivation_is_admin_bit, tc)
{

	ATF_CHECK_MSG(!sctl_rights_is_admin(0),
	    "an empty grant is not admin");
	ATF_CHECK_MSG(!sctl_rights_is_admin((uint64_t)1),
	    "a low-bit right without ADMIN is not admin");
	ATF_CHECK_MSG(!sctl_rights_is_admin(SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN),
	    "every right EXCEPT admin still is not admin");
	ATF_CHECK_MSG(sctl_rights_is_admin(SVC_RIGHTS_ADMIN),
	    "the ADMIN bit alone derives admin");
	ATF_CHECK_MSG(sctl_rights_is_admin(SVC_RIGHTS_ALL),
	    "a full grant includes admin");
	ATF_CHECK_MSG(sctl_rights_is_admin(SVC_RIGHTS_ADMIN | (uint64_t)1),
	    "admin plus other rights is still admin");
}

/*
 * Gap 1 (second half) — a CORE-class unit is unstoppable even WITH admin.  The
 * admin caller clears the sctl rights gate (sctl_op_requires_admin/STOP true,
 * is_admin true => not denied there), but the management-class gate then
 * refuses the stop absolutely, independent of any caller principal.  SYSTEM and
 * USER units are left permitted by the class gate (transport still gates them).
 */
ATF_TC_WITHOUT_HEAD(core_unstoppable_even_with_admin);
ATF_TC_BODY(core_unstoppable_even_with_admin, tc)
{
	bool is_admin = sctl_rights_is_admin(SVC_RIGHTS_ADMIN);
	struct svc_runtime core;

	ATF_REQUIRE(is_admin);
	/* Admin cleared the rights door for STOP... */
	ATF_CHECK(!(sctl_op_requires_admin(SCTL_OP_STOP_SVC) && !is_admin));

	memset(&core, 0, sizeof(core));
	strlcpy(core.manifest.label, "org.test/core", sizeof(core.manifest.label));
	core.manifest.management = SVC_MGMT_CORE;
	core.state = SVC_STATE_RUNNING;

	/* ...but the management-class gate refuses the stop absolutely. */
	ATF_CHECK_EQ_MSG(EPERM, svc_management_check_op(&core, "stopped"),
	    "a CORE unit must be unstoppable even for an admin caller");

	/* SYSTEM / USER units are not refused by the class gate. */
	ATF_CHECK_EQ(0, svc_management_check_class(SVC_MGMT_SYSTEM,
	    "org.test/system", "stopped"));
	ATF_CHECK_EQ(0, svc_management_check_class(SVC_MGMT_USER,
	    "org.test/user", "stopped"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, nonadmin_denied_all_mutating_ops);
	ATF_TP_ADD_TC(tp, admin_passes_all_mutating_ops);
	ATF_TP_ADD_TC(tp, readonly_ops_open_to_nonadmin);
	ATF_TP_ADD_TC(tp, unknown_op_requires_admin);
	ATF_TP_ADD_TC(tp, rights_derivation_is_admin_bit);
	ATF_TP_ADD_TC(tp, core_unstoppable_even_with_admin);

	return (atf_no_error());
}
