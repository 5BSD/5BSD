/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_RUN_H_
#define	_VMM_INTEL_VMX_NESTED_RUN_H_

#include "vmx_nested_types.h"

#include "vmx_nested_context.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_l2_thaw_staged.h"
#include "vmx_nested_refreeze.h"

enum vmx_nested_run_target {
	VMX_NESTED_RUN_L1 = 0,
	VMX_NESTED_RUN_L2_INITIAL,
	VMX_NESTED_RUN_L2_RESUME,
	VMX_NESTED_RUN_INTERNAL,
};

enum vmx_nested_run_unwind_action {
	VMX_NESTED_RUN_UNWIND_CLEAN = 0,
	VMX_NESTED_RUN_UNWIND_ROLLBACK_INITIAL,
	VMX_NESTED_RUN_UNWIND_REFREEZE_UNENTERED,
	VMX_NESTED_RUN_UNWIND_FREEZE_HOT,
	VMX_NESTED_RUN_UNWIND_DETACH_FATAL,
	VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED,
	VMX_NESTED_RUN_UNWIND_FAIL_STOP,
};

/*
 * Value-only ownership facts available at a nested run-loop error boundary.
 * The classifier never performs cleanup; architecture adapters execute the
 * selected inverse operation while the vCPU remains CPU-pinned.
 */
struct vmx_nested_run_unwind_input {
	enum vmx_nested_entry_runtime_state runtime_state;
	enum vmx_nested_l0_continuation_state continuation_state;
	bool portable_valid;
	bool detached;
};

/*
 * Value-only view of the residency owners consulted before entering
 * architecture-specific run code.  No pointer or hardware VMCS identity is
 * retained here.
 */
struct vmx_nested_run_input {
	enum vmx_nested_context_phase context_phase;
	enum vmx_nested_entry_runtime_state runtime_state;
	enum vmx_nested_l0_continuation_state continuation_state;
	enum vmx_nested_l2_thaw_staged_state thaw_state;
	enum vmx_nested_refreeze_state refreeze_state;
	bool plan_valid;
	bool thaw_resources_valid;
	bool internal_pending;
	bool rollback_failed;
};

int	vmx_nested_run_select(const struct vmx_nested_run_input *,
	    enum vmx_nested_run_target *);
int	vmx_nested_run_unwind_select(
	    const struct vmx_nested_run_unwind_input *,
	    enum vmx_nested_run_unwind_action *);

#endif /* _VMM_INTEL_VMX_NESTED_RUN_H_ */
