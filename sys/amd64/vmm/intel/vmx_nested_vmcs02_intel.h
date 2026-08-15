/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_INTEL_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_INTEL_H_

#include <sys/errno.h>
#include "vmx_nested_types.h"

#include "vmx_nested_vmcs02_apply.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_vmcs_launch.h"

struct vmcs;
struct vmx_nested_l2_runtime_state;

/*
 * Intel hardware adapter state.  It is used only while the owning vCPU is
 * frozen in the VMX critical section.  VMCS01 and VMCS02 are distinct,
 * page-aligned, implementation-owned VMCS regions.
 */
struct vmx_nested_vmcs02_intel {
	struct vmcs	*vmcs01;
	struct vmcs	*vmcs02;
	struct vmx_nested_vmcs02_id id;
	uint64_t	resource_generation;
	uint64_t	pending_vmcs01_tsc_offset;
	uint32_t	pending_vmcs01_primary;
	bool		transaction_active;
	bool		pending_vmcs01_tsc;
	struct vmx_nested_vmcs_launch launch;
};

/*
 * Definition-side proof that no hardware VMCS02 transaction or deferred
 * VMCS01 write remains.  The backing VMCS pointers are permanent runtime
 * identity and therefore must remain distinct and non-NULL while inactive.
 */
static __inline int
vmx_nested_vmcs02_intel_inactive_validate(
    const struct vmx_nested_vmcs02_intel *adapter)
{
	int error;

	if (adapter == NULL || adapter->vmcs01 == NULL ||
	    adapter->vmcs02 == NULL)
		return (EINVAL);
	if (adapter->vmcs01 == adapter->vmcs02)
		return (EPROTO);
	error = vmx_nested_vmcs_launch_validate(&adapter->launch);
	if (error != 0)
		return (EPROTO);
	if (adapter->transaction_active || adapter->pending_vmcs01_tsc ||
	    adapter->launch.current)
		return (EBUSY);
	if (adapter->id.state_generation != 0 ||
	    adapter->id.execution_epoch != 0 || adapter->id.vmcs12_gpa != 0 ||
	    adapter->resource_generation != 0 ||
	    adapter->pending_vmcs01_tsc_offset != 0 ||
	    adapter->pending_vmcs01_primary != 0)
		return (EPROTO);
	return (0);
}

static __inline bool
vmx_nested_vmcs02_intel_inactive(
    const struct vmx_nested_vmcs02_intel *adapter)
{

	return (vmx_nested_vmcs02_intel_inactive_validate(adapter) == 0);
}

void	vmx_nested_vmcs02_intel_init(struct vmx_nested_vmcs02_intel *,
	    struct vmcs *, struct vmcs *);
const struct vmx_nested_vmcs02_program_apply_ops *
	vmx_nested_vmcs02_intel_apply_ops(void);
bool	vmx_nested_vmcs02_intel_vmcs01_current(
	    const struct vmx_nested_vmcs02_intel *);
int	vmx_nested_vmcs02_intel_leave(
	    struct vmx_nested_vmcs02_intel *);
int	vmx_nested_vmcs02_intel_entry_instruction(
	    const struct vmx_nested_vmcs02_intel *, int *);
int	vmx_nested_vmcs02_intel_write_guest_pat(
	    struct vmx_nested_vmcs02_intel *,
	    const struct vmx_nested_vmcs02_id *, uint64_t, uint64_t);
int	vmx_nested_vmcs02_intel_write_tsc(
	    struct vmx_nested_vmcs02_intel *,
	    const struct vmx_nested_vmcs02_id *, uint64_t, uint64_t,
	    uint32_t, bool, uint32_t, uint64_t, uint32_t);
int	vmx_nested_vmcs02_intel_commit_entered(
	    struct vmx_nested_vmcs02_intel *);
int	vmx_nested_vmcs02_intel_capture_exit(
	    struct vmx_nested_vmcs02_intel *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    bool,
	    struct vmx_nested_exit_information *,
	    struct vmx_nested_l2_runtime_state *);
/*
 * Capture live L2 architectural state for a software-synthesized nested
 * exit.  No hardware VM-exit-information field is consulted.
 */
int	vmx_nested_vmcs02_intel_capture_runtime(
	    struct vmx_nested_vmcs02_intel *,
	    const struct vmx_nested_vmcs02_id *, uint64_t, bool,
	    struct vmx_nested_l2_runtime_state *);
int	vmx_nested_vmcs02_intel_capture_l2(
	    struct vmx_nested_vmcs02_intel *,
	    const struct vmx_nested_vmcs02_plan *, uint64_t, uint64_t,
	    struct vmx_nested_l2_capture_values *, bool *);
int	vmx_nested_vmcs02_intel_peek_exit(
	    struct vmx_nested_vmcs02_intel *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    struct vmx_nested_exit_information *);
int	vmx_nested_vmcs02_intel_capture_vmcs01_resources(
	    struct vmx_nested_vmcs02_intel *,
	    struct vmx_nested_vmcs02_resources *);
int	vmx_nested_vmcs02_intel_capture_vmcs01_entry_instruction_length(
	    struct vmx_nested_vmcs02_intel *, uint32_t *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_INTEL_H_ */
