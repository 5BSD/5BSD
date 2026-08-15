/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>

#include "vmx_nested_owner_outcome.h"
#include "vmx_nested_state_range.h"

/*
 * Intel-private value adapter for the VMCS02/common-owner bridge.  It is
 * linked into vmm.ko, but deliberately remains outside common VMM state and
 * snapshot formats: common code receives only its portable owner outcome.
 */

int
vmx_nested_owner_outcome_validate(const struct vmx_nested_owner_outcome *outcome)
{
	if (outcome == NULL || outcome->error <= 0)
		return (EINVAL);
	switch (outcome->disposition) {
	case VMX_NESTED_OWNER_OUTCOME_PRESERVE_GUARD:
		return (0);
	case VMX_NESTED_OWNER_OUTCOME_TERMINAL_UNWIND:
		/* A terminal teardown must never be reported as replay. */
		return (outcome->error == EAGAIN ? EINVAL : 0);
	default:
		return (EINVAL);
	}
}

int
vmx_nested_owner_outcome_compose(
    const struct vmx_nested_owner_outcome_input *input,
    struct vmx_nested_owner_outcome *outcome)
{
	struct vmx_nested_owner_outcome candidate;

	if (input == NULL || outcome == NULL || input->guard_error <= 0 ||
	    input->unwind_error < 0 ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), outcome,
	    sizeof(*outcome)))
		return (EINVAL);

	bzero(&candidate, sizeof(candidate));
	switch (input->unwind_action) {
	case VMX_NESTED_RUN_UNWIND_CLEAN:
	case VMX_NESTED_RUN_UNWIND_ROLLBACK_INITIAL:
	case VMX_NESTED_RUN_UNWIND_REFREEZE_UNENTERED:
	case VMX_NESTED_RUN_UNWIND_FREEZE_HOT:
		if (input->unwind_error != 0)
			return (EINVAL);
		candidate.disposition = VMX_NESTED_OWNER_OUTCOME_PRESERVE_GUARD;
		candidate.error = input->guard_error;
		break;
	case VMX_NESTED_RUN_UNWIND_DETACH_FATAL:
	case VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED:
		if (input->unwind_error <= 0 || input->unwind_error == EAGAIN)
			return (EINVAL);
		candidate.disposition = VMX_NESTED_OWNER_OUTCOME_TERMINAL_UNWIND;
		candidate.error = input->unwind_error;
		break;
	case VMX_NESTED_RUN_UNWIND_FAIL_STOP:
	default:
		return (EINVAL);
	}
	if (vmx_nested_owner_outcome_validate(&candidate) != 0)
		return (EINVAL);
	*outcome = candidate;
	return (0);
}

int
vmx_nested_owner_outcome_resolve_preentry(
    struct vmm_startup_entry_owner *owner,
    const struct vmx_nested_owner_outcome *outcome,
    struct vmm_startup_entry_loop_result *result)
{
	int terminal_error;

	if (owner == NULL || outcome == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), outcome,
	    sizeof(*outcome)) || vmx_nested_state_ranges_overlap(owner,
	    sizeof(*owner), result, sizeof(*result)) ||
	    vmx_nested_state_ranges_overlap(outcome,
	    sizeof(*outcome), result, sizeof(*result)))
		return (EINVAL);
	/* Reject mutable storage aliases before interpreting immutable inputs. */
	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    vmx_nested_owner_outcome_validate(outcome) != 0)
		return (EINVAL);
	switch (outcome->disposition) {
	case VMX_NESTED_OWNER_OUTCOME_PRESERVE_GUARD:
		/*
		 * A recoverable private inverse may preserve, but not reinterpret,
		 * the common pre-entry guard captured when the owner was deferred.
		 * Bind the value before resolving it so an adapter cannot silently
		 * present stale replay/error state to a future integration caller.
		 */
		if (outcome->error != owner->deferred.error)
			return (EPROTO);
		terminal_error = 0;
		break;
	case VMX_NESTED_OWNER_OUTCOME_TERMINAL_UNWIND:
		terminal_error = outcome->error;
		break;
	default:
		return (EINVAL);
	}
	return (vmm_startup_entry_owner_resolve_deferred(owner,
	    terminal_error, result));
}

int
vmx_nested_owner_exit_outcome_validate(
    const struct vmx_nested_owner_exit_outcome *outcome)
{

	if (outcome == NULL || outcome->error < 0)
		return (EINVAL);
	switch (outcome->disposition) {
	case VMX_NESTED_OWNER_EXIT_OUTCOME_PRESERVE_RESULT:
		return (0);
	case VMX_NESTED_OWNER_EXIT_OUTCOME_TERMINAL_UNWIND:
		return (outcome->error > 0 && outcome->error != EAGAIN ? 0 :
		    EINVAL);
	default:
		return (EINVAL);
	}
}

int
vmx_nested_owner_exit_outcome_compose(
    const struct vmx_nested_owner_exit_outcome_input *input,
    struct vmx_nested_owner_exit_outcome *outcome)
{
	struct vmx_nested_owner_exit_outcome candidate;

	if (input == NULL || outcome == NULL || input->exit_error < 0 ||
	    input->unwind_error < 0 ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), outcome,
	    sizeof(*outcome)))
		return (EINVAL);

	bzero(&candidate, sizeof(candidate));
	switch (input->unwind_action) {
	case VMX_NESTED_RUN_UNWIND_CLEAN:
	case VMX_NESTED_RUN_UNWIND_FREEZE_HOT:
		if (input->unwind_error != 0)
			return (EINVAL);
		candidate.disposition =
		    VMX_NESTED_OWNER_EXIT_OUTCOME_PRESERVE_RESULT;
		candidate.error = input->exit_error;
		break;
	/*
	 * Both of these inverses prove that L2 never entered.  Accepting either
	 * in the post-entry result domain would allow an attempted-entry failure
	 * to be misreported as a VM exit after the common owner had committed.
	 */
	case VMX_NESTED_RUN_UNWIND_ROLLBACK_INITIAL:
	case VMX_NESTED_RUN_UNWIND_REFREEZE_UNENTERED:
		return (EINVAL);
	case VMX_NESTED_RUN_UNWIND_DETACH_FATAL:
	case VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED:
		if (input->unwind_error <= 0 || input->unwind_error == EAGAIN)
			return (EINVAL);
		candidate.disposition =
		    VMX_NESTED_OWNER_EXIT_OUTCOME_TERMINAL_UNWIND;
		candidate.error = input->unwind_error;
		break;
	case VMX_NESTED_RUN_UNWIND_FAIL_STOP:
	default:
		return (EINVAL);
	}
	if (vmx_nested_owner_exit_outcome_validate(&candidate) != 0)
		return (EINVAL);
	*outcome = candidate;
	return (0);
}

int
vmx_nested_owner_exit_outcome_resolve_postentry(
    struct vmm_startup_entry_owner *owner,
    const struct vmx_nested_owner_exit_outcome *outcome,
    struct vmm_startup_entry_loop_result *result)
{
	int terminal_error;

	if (owner == NULL || outcome == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), outcome,
	    sizeof(*outcome)) || vmx_nested_state_ranges_overlap(owner,
	    sizeof(*owner), result, sizeof(*result)) ||
	    vmx_nested_state_ranges_overlap(outcome,
	    sizeof(*outcome), result, sizeof(*result)))
		return (EINVAL);
	/* Reject mutable storage aliases before interpreting immutable inputs. */
	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    vmx_nested_owner_exit_outcome_validate(outcome) != 0)
		return (EINVAL);
	switch (outcome->disposition) {
	case VMX_NESTED_OWNER_EXIT_OUTCOME_PRESERVE_RESULT:
		/*
		 * The common owner captured the post-entry outcome at the
		 * guard-after-defer boundary.  The private value protocol must
		 * describe that exact outcome; otherwise a stale adapter result
		 * could be accepted while the owner publishes a different replay or
		 * error.  A terminal private unwind is deliberately allowed to
		 * replace it below.
		 */
		if (outcome->error != owner->deferred_exit.error)
			return (EPROTO);
		terminal_error = 0;
		break;
	case VMX_NESTED_OWNER_EXIT_OUTCOME_TERMINAL_UNWIND:
		terminal_error = outcome->error;
		break;
	default:
		return (EINVAL);
	}
	return (vmm_startup_entry_owner_resolve_deferred_after(owner,
	    terminal_error, result));
}

int
vmx_nested_owner_attempt_outcome_validate(
    const struct vmx_nested_owner_attempt_outcome *outcome)
{
	if (outcome == NULL || outcome->disposition >
	    VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR)
		return (EINVAL);
	switch (outcome->disposition) {
	case VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY:
	case VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE:
		return (outcome->error == 0 ? 0 : EINVAL);
	case VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR:
		return (outcome->error > 0 && outcome->error != EAGAIN ? 0 :
		    EINVAL);
	default:
		return (EINVAL);
	}
}

/*
 * An initial attempt has no previously detached portable L2 continuation;
 * its only recoverable inverse is the initial rollback.  A resumed attempt
 * does own that continuation, so its only recoverable inverse is the
 * unentered refreeze.  Both operations leave L2 unentered, but they are not
 * interchangeable: accepting the wrong pair would allow a future caller to
 * settle the common owner while retaining the wrong private residency model.
 */
static bool
nvmxoo_unwind_action_valid(enum vmx_nested_run_unwind_action unwind)
{

	switch (unwind) {
	case VMX_NESTED_RUN_UNWIND_CLEAN:
	case VMX_NESTED_RUN_UNWIND_ROLLBACK_INITIAL:
	case VMX_NESTED_RUN_UNWIND_REFREEZE_UNENTERED:
	case VMX_NESTED_RUN_UNWIND_FREEZE_HOT:
	case VMX_NESTED_RUN_UNWIND_DETACH_FATAL:
	case VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED:
	case VMX_NESTED_RUN_UNWIND_FAIL_STOP:
		return (true);
	default:
		return (false);
	}
}

static bool
nvmxoo_attempt_action_valid(enum vmx_nested_attempt_action action)
{

	switch (action) {
	case VMX_NESTED_ATTEMPT_INITIAL_EXIT:
	case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
	case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
	case VMX_NESTED_ATTEMPT_RESUMED_EXIT:
	case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
	case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
		return (true);
	default:
		return (false);
	}
}

static bool
nvmxoo_initial_attempt_action_valid(enum vmx_nested_attempt_action action)
{

	switch (action) {
	case VMX_NESTED_ATTEMPT_INITIAL_EXIT:
	case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
	case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
		return (true);
	default:
		return (false);
	}
}

static bool
nvmxoo_resumed_attempt_action_valid(enum vmx_nested_attempt_action action)
{

	switch (action) {
	case VMX_NESTED_ATTEMPT_RESUMED_EXIT:
	case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
	case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
		return (true);
	default:
		return (false);
	}
}

static bool
nvmxoo_initial_completion_valid(
    enum vmx_nested_hardware_entry_finish_completion completion)
{

	switch (completion) {
	case VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE:
	case VMX_NESTED_HARDWARE_ENTRY_FINISH_ENTERED:
	case VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK:
		return (true);
	default:
		return (false);
	}
}

static bool
nvmxoo_resumed_completion_valid(
    enum vmx_nested_resumed_hardware_attempt_completion completion)
{

	switch (completion) {
	case VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_NONE:
	case VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_ENTERED:
	case VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN:
		return (true);
	default:
		return (false);
	}
}

static bool
nvmxoo_unwind_matches_unentered_attempt(enum vmx_nested_attempt_action attempt,
    enum vmx_nested_run_unwind_action unwind)
{

	switch (attempt) {
	case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
	case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
		return (unwind == VMX_NESTED_RUN_UNWIND_ROLLBACK_INITIAL);
	case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
	case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
		return (unwind == VMX_NESTED_RUN_UNWIND_REFREEZE_UNENTERED);
	case VMX_NESTED_ATTEMPT_INITIAL_EXIT:
	case VMX_NESTED_ATTEMPT_RESUMED_EXIT:
	default:
		return (false);
	}
}

int
vmx_nested_owner_attempt_outcome_compose(
    const struct vmx_nested_owner_attempt_input *input,
    struct vmx_nested_owner_attempt_outcome *outcome)
{
	struct vmx_nested_owner_attempt_outcome candidate;
	bool no_l2;

	if (input == NULL || outcome == NULL ||
	    !nvmxoo_attempt_action_valid(input->attempt_action) ||
	    !nvmxoo_unwind_action_valid(input->unwind_action) ||
	    input->unwind_error < 0 || input->failure_error < 0 ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), outcome,
	    sizeof(*outcome)))
		return (EINVAL);
	bzero(&candidate, sizeof(candidate));

	/* A real L2 VM exit commits entry before post-entry processing. */
	if (input->attempt_action == VMX_NESTED_ATTEMPT_INITIAL_EXIT ||
	    input->attempt_action == VMX_NESTED_ATTEMPT_RESUMED_EXIT) {
		if (input->unwind_action != VMX_NESTED_RUN_UNWIND_CLEAN ||
		    input->unwind_error != 0 || input->failure_error != 0)
			return (EINVAL);
		candidate.disposition = VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY;
		candidate.error = 0;
		*outcome = candidate;
		return (0);
	}

	no_l2 = input->attempt_action ==
	    VMX_NESTED_ATTEMPT_INITIAL_REJECTION ||
	    input->attempt_action == VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY;
	if (input->unwind_action == VMX_NESTED_RUN_UNWIND_DETACH_FATAL ||
	    input->unwind_action == VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED) {
		if (input->unwind_error <= 0 || input->unwind_error == EAGAIN)
			return (EINVAL);
		candidate.disposition = VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR;
		candidate.error = input->unwind_error;
	} else if (nvmxoo_unwind_matches_unentered_attempt(
	    input->attempt_action, input->unwind_action) &&
	    input->unwind_error == 0) {
		if (no_l2) {
			if (input->failure_error != 0)
				return (EINVAL);
			candidate.disposition =
			    VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE;
			candidate.error = 0;
		} else {
			if (input->failure_error <= 0 ||
			    input->failure_error == EAGAIN)
				return (EINVAL);
			candidate.disposition =
			    VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR;
			candidate.error = input->failure_error;
		}
	} else {
		return (EINVAL);
	}
	if (vmx_nested_owner_attempt_outcome_validate(&candidate) != 0)
		return (EINVAL);
	*outcome = candidate;
	return (0);
}

int
vmx_nested_owner_initial_attempt_outcome_compose(
    const struct vmx_nested_owner_initial_attempt_input *input,
    struct vmx_nested_owner_attempt_outcome *outcome)
{
	struct vmx_nested_owner_attempt_input generic;
	struct vmx_nested_owner_attempt_outcome candidate;

	if (input == NULL || outcome == NULL ||
	    !nvmxoo_initial_attempt_action_valid(input->attempt_action) ||
	    !nvmxoo_initial_completion_valid(input->completion) ||
	    !nvmxoo_unwind_action_valid(input->unwind_action) ||
	    input->unwind_error < 0 || input->failure_error < 0 ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), outcome,
	    sizeof(*outcome)))
		return (EINVAL);
	bzero(&candidate, sizeof(candidate));

	/* A successful first hardware report proves L2 entered; no inverse is pending. */
	if (input->completion == VMX_NESTED_HARDWARE_ENTRY_FINISH_ENTERED) {
		if (input->attempt_action != VMX_NESTED_ATTEMPT_INITIAL_EXIT ||
		    input->unwind_action != VMX_NESTED_RUN_UNWIND_CLEAN ||
		    input->unwind_error != 0 || input->failure_error != 0)
			return (EINVAL);
		candidate.disposition = VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY;
		candidate.error = 0;
	} else if (input->completion ==
	    VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK) {
		if (input->unwind_action != VMX_NESTED_RUN_UNWIND_CLEAN ||
		    input->unwind_error != 0)
			return (EINVAL);
		switch (input->attempt_action) {
		case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
			if (input->failure_error != 0)
				return (EINVAL);
			candidate.disposition =
			    VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE;
			candidate.error = 0;
			break;
		case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
			if (input->failure_error <= 0 ||
			    input->failure_error == EAGAIN)
				return (EINVAL);
			candidate.disposition =
			    VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR;
			candidate.error = input->failure_error;
			break;
		default:
			return (EINVAL);
		}
	} else {
		/* No completion: only the ordinary explicit rollback can settle it. */
		if (input->attempt_action == VMX_NESTED_ATTEMPT_INITIAL_EXIT)
			return (EINVAL);
		generic.attempt_action = input->attempt_action;
		generic.unwind_action = input->unwind_action;
		generic.unwind_error = input->unwind_error;
		generic.failure_error = input->failure_error;
		return (vmx_nested_owner_attempt_outcome_compose(&generic,
		    outcome));
	}
	if (vmx_nested_owner_attempt_outcome_validate(&candidate) != 0)
		return (EINVAL);
	*outcome = candidate;
	return (0);
}

int
vmx_nested_owner_resumed_attempt_outcome_compose(
    const struct vmx_nested_owner_resumed_attempt_input *input,
    struct vmx_nested_owner_attempt_outcome *outcome)
{
	struct vmx_nested_owner_attempt_input generic;
	struct vmx_nested_owner_attempt_outcome candidate;

	if (input == NULL || outcome == NULL ||
	    !nvmxoo_resumed_attempt_action_valid(input->attempt_action) ||
	    !nvmxoo_resumed_completion_valid(input->completion) ||
	    !nvmxoo_unwind_action_valid(input->unwind_action) ||
	    input->unwind_error < 0 || input->failure_error < 0 ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), outcome,
	    sizeof(*outcome)))
		return (EINVAL);
	bzero(&candidate, sizeof(candidate));

	if (input->completion == VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_ENTERED) {
		if (input->attempt_action != VMX_NESTED_ATTEMPT_RESUMED_EXIT ||
		    input->unwind_action != VMX_NESTED_RUN_UNWIND_CLEAN ||
		    input->unwind_error != 0 || input->failure_error != 0)
			return (EINVAL);
		candidate.disposition = VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY;
		candidate.error = 0;
	} else if (input->completion ==
	    VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN) {
		if (input->unwind_action != VMX_NESTED_RUN_UNWIND_CLEAN ||
		    input->unwind_error != 0)
			return (EINVAL);
		switch (input->attempt_action) {
		case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
			if (input->failure_error != 0)
				return (EINVAL);
			candidate.disposition =
			    VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE;
			candidate.error = 0;
			break;
		case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
			if (input->failure_error <= 0 ||
			    input->failure_error == EAGAIN)
				return (EINVAL);
			candidate.disposition =
			    VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR;
			candidate.error = input->failure_error;
			break;
		default:
			return (EINVAL);
		}
	} else {
		if (input->attempt_action == VMX_NESTED_ATTEMPT_RESUMED_EXIT)
			return (EINVAL);
		generic.attempt_action = input->attempt_action;
		generic.unwind_action = input->unwind_action;
		generic.unwind_error = input->unwind_error;
		generic.failure_error = input->failure_error;
		return (vmx_nested_owner_attempt_outcome_compose(&generic,
		    outcome));
	}
	if (vmx_nested_owner_attempt_outcome_validate(&candidate) != 0)
		return (EINVAL);
	*outcome = candidate;
	return (0);
}

int
vmx_nested_owner_attempt_plan_outcome_compose(
    const struct vmx_nested_attempt_plan *attempt,
    enum vmx_nested_run_unwind_action unwind_action, int unwind_error,
    struct vmx_nested_owner_attempt_outcome *outcome)
{
	struct vmx_nested_owner_attempt_input input;
	bool l0_failure;

	if (attempt == NULL || outcome == NULL ||
	    !nvmxoo_unwind_action_valid(unwind_action) || unwind_error < 0 ||
	    vmx_nested_state_ranges_overlap(attempt, sizeof(*attempt), outcome,
	    sizeof(*outcome)))
		return (EINVAL);
	if (vmx_nested_attempt_plan_validate(attempt) != 0)
		return (EINVAL);
	l0_failure = attempt->action == VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE ||
	    attempt->action == VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE;
	input.attempt_action = attempt->action;
	input.unwind_action = unwind_action;
	input.unwind_error = unwind_error;
	input.failure_error = l0_failure ? attempt->host_error : 0;
	return (vmx_nested_owner_attempt_outcome_compose(&input, outcome));
}

int
vmx_nested_owner_attempt_outcome_settle(
    struct vmm_startup_entry_owner *owner,
    const struct vmx_nested_owner_attempt_outcome *outcome,
    struct vmm_startup_entry_loop_result *result)
{

	if (owner == NULL || outcome == NULL)
		return (EINVAL);
	/*
	 * The outcome is an immutable private input.  The common abort operations
	 * already reject an owner/result overlap, but cannot know about this
	 * adapter's extra input.  Reject every remaining overlap before choosing a
	 * disposition so an output buffer cannot clobber the classification.
	 */
	if (vmx_nested_state_ranges_overlap(owner, sizeof(*owner), outcome,
	    sizeof(*outcome)) || (result != NULL &&
	    (vmx_nested_state_ranges_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)) || vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome), result,
	    sizeof(*result)))))
		return (EINVAL);
	/* Do not validate an outcome through storage owned by the caller. */
	if (vmx_nested_owner_attempt_outcome_validate(outcome) != 0)
		return (EINVAL);
	switch (outcome->disposition) {
	case VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY:
		if (result != NULL)
			return (EINVAL);
		return (vmm_startup_entry_owner_commit_attempt(owner));
	case VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE:
		if (result == NULL)
			return (EINVAL);
		return (vmm_startup_entry_owner_abort_attempt(owner, result));
	case VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR:
		if (result == NULL)
			return (EINVAL);
		return (vmm_startup_entry_owner_abort_attempt_error(owner,
		    outcome->error, result));
	default:
		return (EINVAL);
	}
}

/*
 * This intentionally does not resolve a deferred exit.  Its caller must
 * first complete the route-specific Intel-private inverse (EPT walk
 * publication, reflected-exit publication, or hot-continuation freeze), then
 * use vmx_nested_owner_exit_outcome_resolve_postentry().  Keeping those
 * operations on separate sides of this boundary prevents a common result
 * from escaping while VMCS02 or the portable continuation is still owned.
 */
int
vmx_nested_owner_postentry_transition(struct vmm_startup_entry_owner *owner,
    enum vmx_nested_owner_postentry_route route, int backend_error)
{

	if (owner == NULL || route < VMX_NESTED_OWNER_POSTENTRY_RECHECK ||
	    route >= VMX_NESTED_OWNER_POSTENTRY_ROUTE_LAST ||
	    backend_error < 0 || (route == VMX_NESTED_OWNER_POSTENTRY_RECHECK &&
	    backend_error != 0))
		return (EINVAL);
	switch (route) {
	case VMX_NESTED_OWNER_POSTENTRY_RECHECK:
		return (vmm_startup_entry_owner_guard_after(owner, true, 0,
		    NULL));
	case VMX_NESTED_OWNER_POSTENTRY_DEFER_EPT_WALK:
	case VMX_NESTED_OWNER_POSTENTRY_DEFER_REFLECTION:
	case VMX_NESTED_OWNER_POSTENTRY_DEFER_UNHANDLED:
		return (vmm_startup_entry_owner_guard_after_defer(owner,
		    backend_error));
	default:
		return (EINVAL);
	}
}
