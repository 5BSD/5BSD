/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_HARDWARE_ENTRY_H_
#define	_VMM_INTEL_VMX_NESTED_HARDWARE_ENTRY_H_

#include "vmx_nested_types.h"

#include "vmx_nested_context.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_hardware_result.h"
#include "vmx_nested_msr_state.h"
#include "vmx_nested_vmcs02_program.h"

/*
 * Architecture-adapter operations for the final, allocation-free hardware
 * entry boundary.  install_msrs() and program_vmcs02() must report whether
 * every mutation was rolled back when they fail.  A programming failure
 * with incomplete rollback leaves the runtime quarantined; the common layer
 * must not infer VMCS01 residency from an error code alone.
 */
struct vmx_nested_hardware_entry_ops {
	/*
	 * One CPU-pinned transition snapshots this complete table before its
	 * first indirect call.  Callbacks must not sleep, retain arguments, or
	 * mutate the context/runtime ownership objects passed by the caller.
	 */
	int	(*install_msrs)(void *,
		    const struct vmx_nested_software_msrs *, bool *);
	int	(*rollback_msrs)(void *);
	void	(*commit_msrs)(void *);
	void	(*commit_vmcs_launch)(void *);
	int	(*program_vmcs02)(void *,
		    const struct vmx_nested_vmcs02_program *, bool *);
	int	(*leave_vmcs02)(void *);
};

struct vmx_nested_hardware_event_ops {
	void	(*commit_entered)(void *);
	void	(*abort)(void *);
};

/*
 * errno alone cannot describe a failed VMX instruction: an L0-owned failure
 * may have completed the exact VMCS02/MSR rollback before returning its
 * terminal host error.  Keep that completion fact private to the hardware
 * entry boundary so later owner settlement never infers it from a clean
 * runtime state.  A valid invocation first writes NONE and may then publish
 * ENTERED or UNENTERED_ROLLED_BACK; invalid arguments leave the output
 * untouched.  Callers may therefore distinguish an incomplete inverse from
 * a terminal L0 error after a completed unentered rollback.
 */
enum vmx_nested_hardware_entry_finish_completion {
	VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE = 0,
	VMX_NESTED_HARDWARE_ENTRY_FINISH_ENTERED,
	VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK,
};

/*
 * A resumed hardware attempt starts with a retained portable continuation.
 * Its completion must therefore distinguish a real L2 exit from an
 * unentered attempt whose continuation was refrozen.  This describes the
 * hardware/residency boundary itself; a future owner adapter consumes it but
 * does not own the definition.
 */
enum vmx_nested_resumed_hardware_attempt_completion {
	VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_NONE = 0,
	VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_ENTERED,
	VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN,
};

int	vmx_nested_hardware_entry_prepare(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint32_t,
	    const struct vmx_nested_software_msrs *,
	    const struct vmx_nested_vmcs02_program *,
	    const struct vmx_nested_hardware_entry_ops *, void *);
int	vmx_nested_hardware_entry_commit(
	    struct vmx_nested_context *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_hardware_entry_ops *, void *);
int	vmx_nested_hardware_entry_rollback(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_hardware_entry_ops *, void *);
/*
 * A VM exit carrying the failed-entry reason means the VMX instruction
 * completed but L2 never executed.  It has the same hardware unwind as a
 * raw instruction failure, but remains a distinct caller-visible outcome:
 * the pending L0 event is not consumed and VMCS12 receives failed-entry
 * state only after this unwind completes.
 */
int	vmx_nested_hardware_entry_reject(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_hardware_entry_ops *, void *);
/*
 * Resolve the first hardware report after a prepared VMCS02 entry.  Only an
 * ordinary L2 VM-exit commits launch/MSR/context ownership and consumes the
 * pending event.  Both rejection forms unwind hardware without consuming
 * the event and return an immutable rejection for frozen publication.
 */
int	vmx_nested_hardware_entry_finish(
	    struct vmx_nested_context *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_hardware_report_result *,
	    const struct vmx_nested_hardware_entry_ops *, void *,
	    const struct vmx_nested_hardware_event_ops *, void *,
	    enum vmx_nested_hardware_entry_finish_completion *,
	    struct vmx_nested_vmentry_result *);

#endif /* _VMM_INTEL_VMX_NESTED_HARDWARE_ENTRY_H_ */
