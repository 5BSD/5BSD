/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_HANDOFF_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_HANDOFF_H_

#include "vmx_nested_types.h"

#include "vmx_nested_caps.h"
#include "vmx_nested_ept.h"
#include "vmx_nested_ept_fault.h"
#include "vmx_nested_ept_memory.h"
#include "vmx_nested_reflect.h"

enum vmx_nested_ept_handoff_state {
	VMX_NESTED_EPT_HANDOFF_IDLE = 0,
	VMX_NESTED_EPT_HANDOFF_PENDING,
	VMX_NESTED_EPT_HANDOFF_HANDLING,
	VMX_NESTED_EPT_HANDOFF_RESOLVED,
};

/*
 * The two epochs identify the L1 VMCS and the L2 execution that generated
 * the fault.  Both must still match when the frozen-vCPU handler runs.
 */
struct vmx_nested_ept_handoff_id {
	uint64_t vmcs_generation;
	uint64_t execution_epoch;
};

struct vmx_nested_ept_handoff_request {
	struct vmx_nested_ept_handoff_id id;
	struct vmx_nested_capabilities capabilities;
	/*
	 * Complete value-only VMCS02 exit snapshot captured before leaving
	 * the VMX critical section.  Frozen handling must not reload hardware
	 * exit fields after another VMCS may have become current.
	 */
	struct vmx_nested_exit_information vmcs02_exit;
	uint64_t eptp;
	uint64_t l2_gpa;
	uint64_t guest_linear_address;
	uint8_t access;
	bool mode_based_execute;
	bool user_mode;
	bool guest_paging_structure_access;
	bool linear_address_valid;
	bool final_translation;
	bool nmi_unblocking_due_to_iret;
	bool advanced_exit_information;
	bool guest_page_writable;
	bool guest_page_execute_disable;
};

struct vmx_nested_ept_handoff_result {
	struct vmx_nested_ept_handoff_id id;
	struct vmx_nested_ept_fault_plan plan;
	struct vmx_nested_exit_information vmcs02_exit;
	uint64_t guest_physical_address;
	uint64_t guest_linear_address;
	bool guest_linear_address_valid;
};

struct vmx_nested_ept_handoff {
	enum vmx_nested_ept_handoff_state state;
	struct vmx_nested_ept_handoff_request request;
	struct vmx_nested_ept_handoff_result result;
};

struct vmx_nested_ept_handoff_ops {
	int (*populate)(void *, uint64_t, uint64_t, uint8_t, bool);
};

/*
 * The vCPU owner serializes all calls.  publish() is used in the VMX
 * critical section and performs no guest-memory access or backend callback.
 * handle() is used only after vm_run() has returned with the vCPU frozen.
 * It snapshots the memory and optional populate tables before the first
 * callback.  Callbacks cannot retain arguments or mutate the handoff, and
 * changing either caller table cannot redirect the in-flight walk.  Runtime
 * callback pointers and roots are never part of portable state.
 */
void	vmx_nested_ept_handoff_init(struct vmx_nested_ept_handoff *);
int	vmx_nested_ept_handoff_publish(struct vmx_nested_ept_handoff *,
	    const struct vmx_nested_ept_handoff_request *);
int	vmx_nested_ept_handoff_request_prepare(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_exit_information *, uint64_t, bool,
	    struct vmx_nested_ept_handoff_request *);
int	vmx_nested_ept_handoff_handle(struct vmx_nested_ept_handoff *,
	    const struct vmx_nested_ept_handoff_id *,
	    const struct vmx_nested_ept_memory *,
	    const struct vmx_nested_ept_handoff_ops *, void *);
int	vmx_nested_ept_handoff_take(struct vmx_nested_ept_handoff *,
	    const struct vmx_nested_ept_handoff_id *,
	    struct vmx_nested_ept_handoff_result *);
int	vmx_nested_ept_handoff_cancel(struct vmx_nested_ept_handoff *,
	    const struct vmx_nested_ept_handoff_id *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_HANDOFF_H_ */
