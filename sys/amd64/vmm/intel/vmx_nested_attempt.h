/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_ATTEMPT_H_
#define	_VMM_INTEL_VMX_NESTED_ATTEMPT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_hardware_result.h"
#include "vmx_nested_reflect.h"

enum vmx_nested_attempt_kind {
	VMX_NESTED_ATTEMPT_INITIAL = 0,
	VMX_NESTED_ATTEMPT_RESUME,
};

enum vmx_nested_attempt_action {
	VMX_NESTED_ATTEMPT_INITIAL_EXIT = 0,
	VMX_NESTED_ATTEMPT_INITIAL_REJECTION,
	VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE,
	VMX_NESTED_ATTEMPT_RESUMED_EXIT,
	VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY,
	VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE,
};

/*
 * Immutable result of exactly one hardware VMLAUNCH or VMRESUME attempt.
 * A VMEXIT report is accepted only with its matching VMCS02 capture.  Raw
 * VMfail and machine-check reports must not carry an exit capture.
 *
 * host_error is zero for an L2 exit or an L1-visible rejection.  An L0-only
 * report has no host errno in the architectural report format, so the
 * classifier records the explicit host policy error used by a later private
 * unwind/owner transaction.  It is private runtime state, never a VMCS or
 * save-state field.
 */
struct vmx_nested_attempt_plan {
	enum vmx_nested_attempt_action action;
	struct vmx_nested_exit_information exit;
	struct vmx_nested_vmentry_result rejection;
	int		host_error;
	bool		commit_event;
	bool		commit_launch;
};

int	vmx_nested_attempt_classify(enum vmx_nested_attempt_kind,
	    const struct vmx_nested_hardware_report_input *,
	    const struct vmx_nested_exit_information *,
	    struct vmx_nested_attempt_plan *);
int	vmx_nested_attempt_plan_validate(
    const struct vmx_nested_attempt_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_ATTEMPT_H_ */
