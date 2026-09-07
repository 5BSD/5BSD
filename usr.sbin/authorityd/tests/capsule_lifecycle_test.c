/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the Capsule lifecycle-op decision logic
 * (capsule_lifecycle.h): the pure CTL_OP_* -> (howto, Reboot, transition)
 * mapping extracted from capsule_lifecycle_apply(), plus the PID-1 guard
 * predicate from capsule_lifecycle().
 */
#include <sys/reboot.h>

#include <stdbool.h>
#include <unistd.h>

#include <atf-c.h>

#include "authorityd_ctl.h"
#include "capsule_lifecycle.h"

/*
 * The four reboot ops (poweroff/halt/powercycle/reboot) set howto and Reboot
 * and pick death vs death_single from the current state's teardown depth.
 */
ATF_TC_WITHOUT_HEAD(reboot_ops_set_howto_and_death);
ATF_TC_BODY(reboot_ops_set_howto_and_death, tc)
{
	struct capsule_lc_action a;

	/* to_death=true => full death path. */
	a = capsule_lifecycle_decide(CTL_OP_POWEROFF, true, true);
	ATF_CHECK(a.valid);
	ATF_CHECK(a.set_howto);
	ATF_CHECK_EQ(RB_HALT | RB_POWEROFF, a.howto);
	ATF_CHECK(a.set_reboot && a.reboot);
	ATF_CHECK_EQ(CAPSULE_LC_DEATH, a.trans);

	a = capsule_lifecycle_decide(CTL_OP_HALT, true, true);
	ATF_CHECK_EQ(RB_HALT, a.howto);
	ATF_CHECK_EQ(CAPSULE_LC_DEATH, a.trans);

	a = capsule_lifecycle_decide(CTL_OP_POWERCYCLE, true, true);
	ATF_CHECK_EQ(RB_POWERCYCLE, a.howto);
	ATF_CHECK_EQ(CAPSULE_LC_DEATH, a.trans);

	a = capsule_lifecycle_decide(CTL_OP_REBOOT, true, true);
	ATF_CHECK_EQ(RB_AUTOBOOT, a.howto);
	ATF_CHECK(a.set_reboot && a.reboot);
	ATF_CHECK_EQ(CAPSULE_LC_DEATH, a.trans);

	/* to_death=false => minimal teardown (death_single), same howto. */
	a = capsule_lifecycle_decide(CTL_OP_REBOOT, false, false);
	ATF_CHECK_EQ(RB_AUTOBOOT, a.howto);
	ATF_CHECK_EQ(CAPSULE_LC_DEATH_SINGLE, a.trans);
}

/*
 * SINGLE clears Reboot but must NOT set howto (leaves the field the caller
 * owns untouched), and picks death vs death_single like the reboot ops.
 */
ATF_TC_WITHOUT_HEAD(single_clears_reboot_keeps_howto);
ATF_TC_BODY(single_clears_reboot_keeps_howto, tc)
{
	struct capsule_lc_action a;

	a = capsule_lifecycle_decide(CTL_OP_SINGLE, true, true);
	ATF_CHECK(a.valid);
	ATF_CHECK_MSG(!a.set_howto, "SINGLE must not touch howto");
	ATF_CHECK(a.set_reboot);
	ATF_CHECK_MSG(!a.reboot, "SINGLE must clear Reboot");
	ATF_CHECK_EQ(CAPSULE_LC_DEATH, a.trans);

	a = capsule_lifecycle_decide(CTL_OP_SINGLE, false, false);
	ATF_CHECK(!a.set_howto);
	ATF_CHECK(a.set_reboot && !a.reboot);
	ATF_CHECK_EQ(CAPSULE_LC_DEATH_SINGLE, a.trans);
}

/* REROOT requests the reroot transition and touches neither howto nor Reboot. */
ATF_TC_WITHOUT_HEAD(reroot_touches_nothing_else);
ATF_TC_BODY(reroot_touches_nothing_else, tc)
{
	struct capsule_lc_action a;

	a = capsule_lifecycle_decide(CTL_OP_REROOT, true, true);
	ATF_CHECK(a.valid);
	ATF_CHECK(!a.set_howto);
	ATF_CHECK(!a.set_reboot);
	ATF_CHECK_EQ(CAPSULE_LC_REROOT, a.trans);
}

/* RESCAN maps to clean_ttys only from a to_death state; otherwise no-op. */
ATF_TC_WITHOUT_HEAD(rescan_is_state_gated);
ATF_TC_BODY(rescan_is_state_gated, tc)
{
	struct capsule_lc_action a;

	a = capsule_lifecycle_decide(CTL_OP_RESCAN, true, true);
	ATF_CHECK(a.valid);
	ATF_CHECK_EQ(CAPSULE_LC_CLEAN_TTYS, a.trans);

	a = capsule_lifecycle_decide(CTL_OP_RESCAN, false, false);
	ATF_CHECK(a.valid);
	ATF_CHECK_EQ_MSG(CAPSULE_LC_NONE, a.trans,
	    "RESCAN outside a to_death state must be a no-op");
}

/* CATATONIA maps to catatonia only when the current state accepts it. */
ATF_TC_WITHOUT_HEAD(catatonia_is_state_gated);
ATF_TC_BODY(catatonia_is_state_gated, tc)
{
	struct capsule_lc_action a;

	a = capsule_lifecycle_decide(CTL_OP_CATATONIA, false, true);
	ATF_CHECK(a.valid);
	ATF_CHECK_EQ(CAPSULE_LC_CATATONIA, a.trans);

	a = capsule_lifecycle_decide(CTL_OP_CATATONIA, false, false);
	ATF_CHECK(a.valid);
	ATF_CHECK_EQ_MSG(CAPSULE_LC_NONE, a.trans,
	    "CATATONIA from a non-accepting state must be a no-op");
}

/* An unknown op is flagged invalid and changes nothing. */
ATF_TC_WITHOUT_HEAD(unknown_op_is_invalid);
ATF_TC_BODY(unknown_op_is_invalid, tc)
{
	struct capsule_lc_action a;

	a = capsule_lifecycle_decide(0x7fffffff, true, true);
	ATF_CHECK_MSG(!a.valid, "an unrecognized op must be invalid");
	ATF_CHECK(!a.set_howto);
	ATF_CHECK(!a.set_reboot);
	ATF_CHECK_EQ(CAPSULE_LC_NONE, a.trans);
}

/* The PID-1 guard: only pid 1 may drive a lifecycle transition. */
ATF_TC_WITHOUT_HEAD(lifecycle_permits_only_pid1);
ATF_TC_BODY(lifecycle_permits_only_pid1, tc)
{

	ATF_CHECK(capsule_lifecycle_permits(1));
	ATF_CHECK(!capsule_lifecycle_permits(0));
	ATF_CHECK(!capsule_lifecycle_permits(2));
	ATF_CHECK(!capsule_lifecycle_permits(getpid()));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, reboot_ops_set_howto_and_death);
	ATF_TP_ADD_TC(tp, single_clears_reboot_keeps_howto);
	ATF_TP_ADD_TC(tp, reroot_touches_nothing_else);
	ATF_TP_ADD_TC(tp, rescan_is_state_gated);
	ATF_TP_ADD_TC(tp, catatonia_is_state_gated);
	ATF_TP_ADD_TC(tp, unknown_op_is_invalid);
	ATF_TP_ADD_TC(tp, lifecycle_permits_only_pid1);
	return (atf_no_error());
}
