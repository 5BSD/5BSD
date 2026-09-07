/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Capsule lifecycle-op decision logic.
 *
 * capsule_lifecycle_apply() (capsule.c) translates an authenticated lifecycle
 * request serviced relayed (CTL_OP_*) into howto/Reboot/requested_transition on
 * the PID-1 state machine.  The pure op -> action mapping — which is identical
 * to the retired signal mapping (init behavior audit §14) and is
 * current-state-sensitive — is factored out here so it is unit-testable without
 * the file-static globals or the state-function pointers.  capsule_lifecycle()'s
 * PID-1 guard is likewise expressed as a pure predicate.  Behavior-preserving
 * extraction: the caller applies the returned action verbatim.
 */
#ifndef CAPSULE_LIFECYCLE_H
#define CAPSULE_LIFECYCLE_H

#include <sys/reboot.h>

#include <stdbool.h>

#include "authorityd_ctl.h"	/* CTL_OP_* */

/*
 * Which state-machine transition a lifecycle op requests.  NONE means the op
 * leaves requested_transition untouched (its guard state was not satisfied, or
 * the op is unknown).  The DEATH/DEATH_SINGLE split is the "full teardown vs
 * minimal teardown" choice the caller resolves from the current state.
 */
enum capsule_lc_trans {
	CAPSULE_LC_NONE = 0,
	CAPSULE_LC_DEATH,
	CAPSULE_LC_DEATH_SINGLE,
	CAPSULE_LC_REROOT,
	CAPSULE_LC_CLEAN_TTYS,
	CAPSULE_LC_CATATONIA,
};

/*
 * The decision for one lifecycle op.  howto/reboot are applied only when their
 * set_* flag is true (SINGLE clears Reboot but must not touch howto; REROOT and
 * the tty ops touch neither).  valid is false for an unrecognized op, for which
 * the caller logs and does nothing.
 */
struct capsule_lc_action {
	bool	valid;
	bool	set_howto;
	int	howto;
	bool	set_reboot;
	bool	reboot;
	enum capsule_lc_trans trans;
};

/*
 * Decide the action for op.  to_death is true when the current state runs the
 * full death path (read_ttys/multi_user/clean_ttys/catatonia); catatonia_ok is
 * true when the current state accepts a catatonia request (runcom/read_ttys/
 * clean_ttys/multi_user/catatonia).  Both are computed by the caller from
 * current_state.  Mirrors capsule_lifecycle_apply()'s switch exactly.
 */
static inline struct capsule_lc_action
capsule_lifecycle_decide(int op, bool to_death, bool catatonia_ok)
{
	struct capsule_lc_action a;

	a.valid = true;
	a.set_howto = false;
	a.howto = 0;
	a.set_reboot = false;
	a.reboot = false;
	a.trans = CAPSULE_LC_NONE;

	switch (op) {
	case CTL_OP_POWEROFF:
		a.set_howto = true;
		a.howto = RB_HALT | RB_POWEROFF;
		a.set_reboot = true;
		a.reboot = true;
		a.trans = to_death ? CAPSULE_LC_DEATH : CAPSULE_LC_DEATH_SINGLE;
		break;
	case CTL_OP_HALT:
		a.set_howto = true;
		a.howto = RB_HALT;
		a.set_reboot = true;
		a.reboot = true;
		a.trans = to_death ? CAPSULE_LC_DEATH : CAPSULE_LC_DEATH_SINGLE;
		break;
	case CTL_OP_POWERCYCLE:
		a.set_howto = true;
		a.howto = RB_POWERCYCLE;
		a.set_reboot = true;
		a.reboot = true;
		a.trans = to_death ? CAPSULE_LC_DEATH : CAPSULE_LC_DEATH_SINGLE;
		break;
	case CTL_OP_REBOOT:
		a.set_howto = true;
		a.howto = RB_AUTOBOOT;
		a.set_reboot = true;
		a.reboot = true;
		a.trans = to_death ? CAPSULE_LC_DEATH : CAPSULE_LC_DEATH_SINGLE;
		break;
	case CTL_OP_SINGLE:
		a.set_reboot = true;
		a.reboot = false;
		a.trans = to_death ? CAPSULE_LC_DEATH : CAPSULE_LC_DEATH_SINGLE;
		break;
	case CTL_OP_REROOT:
		a.trans = CAPSULE_LC_REROOT;
		break;
	case CTL_OP_RESCAN:
		if (to_death)
			a.trans = CAPSULE_LC_CLEAN_TTYS;
		break;
	case CTL_OP_CATATONIA:
		if (catatonia_ok)
			a.trans = CAPSULE_LC_CATATONIA;
		break;
	default:
		a.valid = false;
		break;
	}
	return (a);
}

/*
 * capsule_lifecycle() only drives a transition when Authority is PID 1: a
 * plane-free boot runs stock init and has no lifecycle authority here.
 */
static inline bool
capsule_lifecycle_permits(pid_t pid)
{

	return (pid == 1);
}

#endif /* CAPSULE_LIFECYCLE_H */
