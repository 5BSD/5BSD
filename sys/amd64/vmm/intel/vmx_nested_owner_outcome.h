/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_OWNER_OUTCOME_H_
#define	_VMM_INTEL_VMX_NESTED_OWNER_OUTCOME_H_

#include <sys/types.h>

#include <dev/vmm/vmm_startup_entry_owner.h>

#include "vmx_nested_attempt.h"
#include "vmx_nested_hardware_entry.h"
#include "vmx_nested_run.h"

/*
 * This is Intel-private glue for the cold/resumed/hot VMCS02 owner
 * transaction.  It is linked into vmm.ko but remains outside common VMM
 * state, save-state images, and public headers.  It converts completed
 * Intel-private inverses into the portable startup-owner protocol; it does
 * not itself acquire machine state or enable nested-VMX guest exposure.
 */

/*
 * A common startup-entry owner may already have selected a replay or an
 * error when nested VMX discovers which residency unwind is required.  This
 * value protocol makes that precedence explicit without exporting VMCS02
 * residency, stack ownership, or an Intel-specific result through a common
 * save-state interface.
 */
enum vmx_nested_owner_outcome_disposition {
	VMX_NESTED_OWNER_OUTCOME_PRESERVE_GUARD = 0,
	VMX_NESTED_OWNER_OUTCOME_TERMINAL_UNWIND,
};

struct vmx_nested_owner_outcome_input {
	enum vmx_nested_run_unwind_action unwind_action;
	int guard_error;
	int unwind_error;
};

struct vmx_nested_owner_outcome {
	enum vmx_nested_owner_outcome_disposition disposition;
	int error;
};

int	vmx_nested_owner_outcome_compose(
	    const struct vmx_nested_owner_outcome_input *,
	    struct vmx_nested_owner_outcome *);
int	vmx_nested_owner_outcome_validate(
	    const struct vmx_nested_owner_outcome *);
/*
 * Resolve a previously composed pre-entry result only after its Intel-private
 * inverse has finished.  The outcome is immutable; this adapter neither
 * selects nor performs VMCS02 cleanup.
 */
int	vmx_nested_owner_outcome_resolve_preentry(
	    struct vmm_startup_entry_owner *,
	    const struct vmx_nested_owner_outcome *,
	    struct vmm_startup_entry_loop_result *);

/*
 * Post-entry composition deliberately has a different result domain: an
 * actual VM exit is represented by zero, unlike a declined pre-entry guard.
 * Keep that distinction explicit so a caller cannot reinterpret one as the
 * other merely because both may require a private residency unwind.
 */
enum vmx_nested_owner_exit_outcome_disposition {
	VMX_NESTED_OWNER_EXIT_OUTCOME_PRESERVE_RESULT = 0,
	VMX_NESTED_OWNER_EXIT_OUTCOME_TERMINAL_UNWIND,
};

struct vmx_nested_owner_exit_outcome_input {
	enum vmx_nested_run_unwind_action unwind_action;
	int exit_error;
	int unwind_error;
};

struct vmx_nested_owner_exit_outcome {
	enum vmx_nested_owner_exit_outcome_disposition disposition;
	int error;
};

int	vmx_nested_owner_exit_outcome_compose(
	    const struct vmx_nested_owner_exit_outcome_input *,
	    struct vmx_nested_owner_exit_outcome *);
int	vmx_nested_owner_exit_outcome_validate(
	    const struct vmx_nested_owner_exit_outcome *);
/*
 * Resolve a captured L2 exit only after its Intel-private post-entry inverse
 * has completed.  This is deliberately distinct from the pre-entry adapter:
 * zero means a preserved VM exit in this result domain.
 */
int	vmx_nested_owner_exit_outcome_resolve_postentry(
	    struct vmm_startup_entry_owner *,
	    const struct vmx_nested_owner_exit_outcome *,
	    struct vmm_startup_entry_loop_result *);

/*
 * A pending common owner must settle an immutable hardware-attempt result
 * before the ordinary post-entry exit domain begins.  This Intel-private
 * value model selects one portable action only after the corresponding
 * private inverse has completed; it does not own VMCS02 or execute cleanup.
 */
enum vmx_nested_owner_attempt_disposition {
	VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY = 0,
	VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE,
	VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR,
};

struct vmx_nested_owner_attempt_input {
	enum vmx_nested_attempt_action attempt_action;
	enum vmx_nested_run_unwind_action unwind_action;
	int	unwind_error;
	int	failure_error;
};

struct vmx_nested_owner_attempt_outcome {
	enum vmx_nested_owner_attempt_disposition disposition;
	int	error;
};

int	vmx_nested_owner_attempt_outcome_compose(
	    const struct vmx_nested_owner_attempt_input *,
	    struct vmx_nested_owner_attempt_outcome *);
/*
 * Translate an immutable attempt plan without allowing a later caller to
 * recreate its host-error policy.  This remains Intel-private glue.
 */
int	vmx_nested_owner_attempt_plan_outcome_compose(
    const struct vmx_nested_attempt_plan *,
    enum vmx_nested_run_unwind_action, int,
    struct vmx_nested_owner_attempt_outcome *);
int	vmx_nested_owner_attempt_outcome_validate(
	    const struct vmx_nested_owner_attempt_outcome *);

/*
 * The first VMCS02 attempt is finalized by hardware_entry_finish().  Its
 * rejection and L0-failure paths can complete the exact inverse before
 * returning to vmx_run_nested(), so an owner outcome must retain that fact
 * rather than require a second, fictitious generic rollback.
 */
struct vmx_nested_owner_initial_attempt_input {
	enum vmx_nested_attempt_action attempt_action;
	enum vmx_nested_hardware_entry_finish_completion completion;
	enum vmx_nested_run_unwind_action unwind_action;
	int	unwind_error;
	int	failure_error;
};

int	vmx_nested_owner_initial_attempt_outcome_compose(
	    const struct vmx_nested_owner_initial_attempt_input *,
	    struct vmx_nested_owner_attempt_outcome *);

struct vmx_nested_owner_resumed_attempt_input {
	enum vmx_nested_attempt_action attempt_action;
	enum vmx_nested_resumed_hardware_attempt_completion completion;
	enum vmx_nested_run_unwind_action unwind_action;
	int	unwind_error;
	int	failure_error;
};

int	vmx_nested_owner_resumed_attempt_outcome_compose(
	    const struct vmx_nested_owner_resumed_attempt_input *,
	    struct vmx_nested_owner_attempt_outcome *);
/*
 * Apply a previously validated Intel-private value result to a portable
 * pending owner.  Commit deliberately has no loop result; aborts require one.
 */
int	vmx_nested_owner_attempt_outcome_settle(
	    struct vmm_startup_entry_owner *,
	    const struct vmx_nested_owner_attempt_outcome *,
	    struct vmm_startup_entry_loop_result *);

/*
 * A committed L2 entry has two distinct common-owner post-entry transitions.
 * A locally handled VM exit returns to RECHECK before another VM-entry
 * attempt.  Every exit that must first publish a frozen L1-visible result
 * remains DEFERRED until that private operation has completed.  For a
 * deferred route, backend_error is the already-classified post-entry result:
 * zero is a VM exit, EAGAIN requests replay, and any other positive errno is
 * terminal.  A locally handled recheck has no result to retain and therefore
 * requires zero.  Keep EPT and
 * direct reflection separate from the generic unhandled case: their private
 * publication mechanisms differ even though their common-owner transition is
 * identical.
 */
enum vmx_nested_owner_postentry_route {
	VMX_NESTED_OWNER_POSTENTRY_RECHECK = 0,
	VMX_NESTED_OWNER_POSTENTRY_DEFER_EPT_WALK,
	VMX_NESTED_OWNER_POSTENTRY_DEFER_REFLECTION,
	VMX_NESTED_OWNER_POSTENTRY_DEFER_UNHANDLED,
	VMX_NESTED_OWNER_POSTENTRY_ROUTE_LAST,
};

int	vmx_nested_owner_postentry_transition(
	    struct vmm_startup_entry_owner *,
	    enum vmx_nested_owner_postentry_route, int);

#endif /* _VMM_INTEL_VMX_NESTED_OWNER_OUTCOME_H_ */
