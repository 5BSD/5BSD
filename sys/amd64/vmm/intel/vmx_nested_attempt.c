/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_attempt.h"
#include "vmx_nested_state_range.h"

#define	NVMXA_ENTRY_FAILURE	(UINT32_C(1) << 31)

static bool
nvmxa_exit_matches(const struct vmx_nested_hardware_report_input *report,
    const struct vmx_nested_exit_information *exit)
{

	return (exit != NULL && report->exit_reason == exit->exit_reason &&
	    report->exit_qualification == exit->exit_qualification &&
	    report->exit_instruction_length ==
	    exit->exit_instruction_length);
}

static bool
nvmxa_exit_empty(const struct vmx_nested_exit_information *exit)
{
	struct vmx_nested_exit_information zero;

	memset(&zero, 0, sizeof(zero));
	/*
	 * This is a value contract, not a serialized image.  In particular, the
	 * trailing padding after launched is not architectural state and must not
	 * make an otherwise empty private plan depend on compiler layout.
	 */
	return (vmx_nested_exit_information_equal(exit, &zero));
}

static bool
nvmxa_rejection_empty(const struct vmx_nested_vmentry_result *rejection)
{
	struct vmx_nested_vmentry_result zero;

	memset(&zero, 0, sizeof(zero));
	return (vmx_nested_vmentry_result_equal(rejection, &zero));
}

/*
 * A plan is passed between private adapters after the capture buffer is no
 * longer in scope.  Check the complete value contract here rather than only
 * the action flags: otherwise a stale VMCS02 exit/rejection payload could be
 * accepted by a later adapter that never saw the original hardware report.
 */
static bool
nvmxa_exit_valid(const struct vmx_nested_exit_information *exit, bool failed)
{
	struct vmx_nested_exit_information normalized, zero;

	memset(&zero, 0, sizeof(zero));
	if (((exit->exit_reason & NVMXA_ENTRY_FAILURE) != 0) != failed ||
	    vmx_nested_exit_information_prepare(&zero, exit, &normalized) != 0)
		return (false);
	return (vmx_nested_exit_information_equal(exit, &normalized));
}

static bool
nvmxa_failed_entry_valid(const struct vmx_nested_exit_information *exit)
{
	struct vmx_nested_vmentry_result rejection;

	/*
	 * Entry failure is not sufficient here: MSR-load failure and machine
	 * check are L0-owned in VMCS02 and must not be reintroduced as an L1
	 * VMRESUME failure through a crafted private plan.
	 */
	return (nvmxa_exit_valid(exit, true) &&
	    vmx_nested_vmentry_hardware_failed_entry(exit->exit_reason,
	    exit->exit_qualification, 0, &rejection) == 0);
}

int
vmx_nested_attempt_plan_validate(const struct vmx_nested_attempt_plan *plan)
{

	if (plan == NULL)
		return (EINVAL);
	switch (plan->action) {
	case VMX_NESTED_ATTEMPT_INITIAL_EXIT:
		return (plan->host_error == 0 && plan->commit_event &&
		    plan->commit_launch && nvmxa_exit_valid(&plan->exit, false) &&
		    nvmxa_rejection_empty(&plan->rejection) ? 0 : EINVAL);
	case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
		return (plan->host_error == 0 && !plan->commit_event &&
		    !plan->commit_launch && nvmxa_exit_empty(&plan->exit) &&
		    vmx_nested_vmentry_rejection_validate(&plan->rejection) == 0 ?
		    0 : EINVAL);
	case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
		return (plan->host_error == 0 && !plan->commit_event &&
		    !plan->commit_launch && nvmxa_failed_entry_valid(&plan->exit) &&
		    nvmxa_rejection_empty(&plan->rejection) ? 0 : EINVAL);
	case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
	case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
		return (plan->host_error == EIO && !plan->commit_event &&
		    !plan->commit_launch && nvmxa_exit_empty(&plan->exit) &&
		    nvmxa_rejection_empty(&plan->rejection) ? 0 : EINVAL);
	case VMX_NESTED_ATTEMPT_RESUMED_EXIT:
		return (plan->host_error == 0 && plan->commit_event &&
		    !plan->commit_launch && nvmxa_exit_valid(&plan->exit, false) &&
		    nvmxa_rejection_empty(&plan->rejection) ? 0 : EINVAL);
	default:
		return (EINVAL);
	}
}

int
vmx_nested_attempt_classify(enum vmx_nested_attempt_kind kind,
    const struct vmx_nested_hardware_report_input *report,
    const struct vmx_nested_exit_information *exit,
    struct vmx_nested_attempt_plan *plan)
{
	struct vmx_nested_hardware_report_result hardware;
	struct vmx_nested_attempt_plan candidate;
	struct vmx_nested_exit_information captured_exit, zero_exit;
	int error;

	if (kind < VMX_NESTED_ATTEMPT_INITIAL ||
	    kind > VMX_NESTED_ATTEMPT_RESUME || report == NULL ||
	    plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), report,
	    sizeof(*report)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), exit,
	    sizeof(*exit)) || report->report <
	    VMX_NESTED_HARDWARE_REPORT_VMEXIT || report->report >
	    VMX_NESTED_HARDWARE_REPORT_MACHINE_CHECK)
		return (EINVAL);
	if (report->report == VMX_NESTED_HARDWARE_REPORT_VMEXIT) {
		if (!nvmxa_exit_matches(report, exit))
			return (EINVAL);
		/*
		 * Preserve a canonical capture in the plan.  The hardware-report
		 * input binds its three architectural report fields to exit, while
		 * this normalizes and validates the remaining VMCS02 exit image
		 * before the caller's buffer goes out of scope.
		 */
		memset(&zero_exit, 0, sizeof(zero_exit));
		if (vmx_nested_exit_information_prepare(&zero_exit, exit,
		    &captured_exit) != 0)
			return (EINVAL);
	} else if (exit != NULL) {
		/*
		 * VMfail and machine check do not make VMCS exit fields valid.
		 * Rejecting a parallel capture prevents stale VMCS02 state from
		 * being mistaken for the result of this attempt.
		 */
		return (EINVAL);
	}
	error = vmx_nested_hardware_report_classify(report, &hardware);
	if (error != 0)
		return (error);

	memset(&candidate, 0, sizeof(candidate));
	if (kind == VMX_NESTED_ATTEMPT_INITIAL) {
		switch (hardware.disposition) {
		case VMX_NESTED_HARDWARE_L2_EXIT:
			candidate.action = VMX_NESTED_ATTEMPT_INITIAL_EXIT;
			candidate.exit = captured_exit;
			candidate.commit_event = true;
			candidate.commit_launch = true;
			break;
		case VMX_NESTED_HARDWARE_REJECTION:
			candidate.action =
			    VMX_NESTED_ATTEMPT_INITIAL_REJECTION;
			candidate.rejection = hardware.rejection;
			break;
		case VMX_NESTED_HARDWARE_L0_FAILURE:
			candidate.action =
			    VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE;
			/* VMX supplies a report, not an L0 errno. */
			candidate.host_error = EIO;
			break;
		}
	} else if (report->report !=
	    VMX_NESTED_HARDWARE_REPORT_VMEXIT) {
		/*
		 * A resumed VMCS02 remains represented by its portable L2
		 * image until hardware proves entry.  Raw L0 failure therefore
		 * requires refreezing that retained image, never reflection as
		 * the result of L1's earlier VMX instruction.
		 */
		candidate.action = VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE;
		candidate.host_error = EIO;
	} else {
		switch (hardware.disposition) {
		case VMX_NESTED_HARDWARE_L2_EXIT:
			candidate.action =
			    VMX_NESTED_ATTEMPT_RESUMED_EXIT;
			candidate.exit = captured_exit;
			candidate.commit_event = true;
			break;
		case VMX_NESTED_HARDWARE_REJECTION:
			candidate.action =
			    VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY;
			candidate.exit = captured_exit;
			break;
		case VMX_NESTED_HARDWARE_L0_FAILURE:
			candidate.action =
			    VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE;
			candidate.host_error = EIO;
			break;
		}
	}
	if (vmx_nested_attempt_plan_validate(&candidate) != 0)
		return (EINVAL);
	*plan = candidate;
	return (0);
}
