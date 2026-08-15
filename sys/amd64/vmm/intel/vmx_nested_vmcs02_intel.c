/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <vm/vm.h>
#include <vm/pmap.h>

struct seg_desc;
struct vmx;
struct vmx_vcpu;

#include "vmx_controls.h"
#include "vmx_cpufunc.h"
#include "vmcs.h"
#include "vmx_nested_exit_capture.h"
#include "vmx_nested_vmcs02_intel.h"
#include "vmx_nested_vmcs_fields.h"
#include "vmx_nested_vmexit.h"
#include "vmx_msr.h"

static bool
nvmxi_current_is(const struct vmcs *vmcs)
{
	uint64_t current;

	vmptrst(&current);
	return (current == vtophys(vmcs));
}

static bool
nvmxi_exit_capture_valid(const struct vmx_nested_vmcs02_intel *adapter,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation)
{

	return (adapter != NULL && vmx_nested_vmcs02_id_valid(id) &&
	    !adapter->transaction_active && adapter->launch.current &&
	    resource_generation != 0 &&
	    vmx_nested_vmcs02_id_equal(id, &adapter->id) &&
	    resource_generation == adapter->resource_generation &&
	    curthread->td_critnest != 0 &&
	    nvmxi_current_is(adapter->vmcs02));
}

static int
nvmxi_read_exit_field(void *arg, enum vmx_nested_exit_capture_field field,
    uint64_t *value)
{
	struct vmx_nested_vmcs02_intel *adapter;
	uint32_t encoding;

	adapter = arg;
	if (adapter == NULL || value == NULL || !adapter->launch.current ||
	    adapter->transaction_active || curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs02))
		return (EINVAL);

	switch (field) {
	case VMX_NESTED_EXIT_CAPTURE_QUALIFICATION:
		encoding = VMCS_EXIT_QUALIFICATION;
		break;
	case VMX_NESTED_EXIT_CAPTURE_GUEST_LINEAR_ADDRESS:
		encoding = VMCS_GUEST_LINEAR_ADDRESS;
		break;
	case VMX_NESTED_EXIT_CAPTURE_GUEST_PHYSICAL_ADDRESS:
		encoding = VMCS_GUEST_PHYSICAL_ADDRESS;
		break;
	case VMX_NESTED_EXIT_CAPTURE_REASON:
		encoding = VMCS_EXIT_REASON;
		break;
	case VMX_NESTED_EXIT_CAPTURE_INTERRUPTION_INFO:
		encoding = VMCS_EXIT_INTR_INFO;
		break;
	case VMX_NESTED_EXIT_CAPTURE_INTERRUPTION_ERROR:
		encoding = VMCS_EXIT_INTR_ERRCODE;
		break;
	case VMX_NESTED_EXIT_CAPTURE_IDT_VECTORING_INFO:
		encoding = VMCS_IDT_VECTORING_INFO;
		break;
	case VMX_NESTED_EXIT_CAPTURE_IDT_VECTORING_ERROR:
		encoding = VMCS_IDT_VECTORING_ERROR;
		break;
	case VMX_NESTED_EXIT_CAPTURE_INSTRUCTION_LENGTH:
		encoding = VMCS_EXIT_INSTRUCTION_LENGTH;
		break;
	case VMX_NESTED_EXIT_CAPTURE_INSTRUCTION_INFO:
		encoding = VMCS_EXIT_INSTRUCTION_INFO;
		break;
	case VMX_NESTED_EXIT_CAPTURE_ENTRY_INTERRUPTION_INFO:
		encoding = VMCS_ENTRY_INTR_INFO;
		break;
	default:
		return (EINVAL);
	}
	return (vmread(encoding, value) == 0 ? 0 : EIO);
}

static const struct vmx_nested_exit_capture_ops nvmxi_exit_capture_ops = {
	.read = nvmxi_read_exit_field,
};

/* Intel SDM Vol. 3C, secondary processor-based execution controls. */
#define	NVMXI_VIRTUAL_INTERRUPT_DELIVERY	(UINT32_C(1) << 9)

static int
nvmxi_restore_vmcs01(struct vmx_nested_vmcs02_intel *adapter)
{
	uint64_t old_offset, old_primary;
	int error;

	if (!nvmxi_current_is(adapter->vmcs02))
		return (EINVAL);
	error = vmclear(adapter->vmcs02);
	if (error != VM_SUCCESS)
		panic("%s: cannot detach VMCS02: %d", __func__, error);
	if (vmptrld(adapter->vmcs01) != 0)
		panic("%s: cannot restore current VMCS01", __func__);
	error = 0;
	if (adapter->pending_vmcs01_tsc) {
		if (vmread(VMCS_TSC_OFFSET, &old_offset) != 0 ||
		    vmread(VMCS_PRI_PROC_BASED_CTLS, &old_primary) != 0 ||
		    old_primary > UINT32_MAX) {
			error = EIO;
		} else if (vmwrite(VMCS_TSC_OFFSET,
		    adapter->pending_vmcs01_tsc_offset) != 0 ||
		    vmwrite(VMCS_PRI_PROC_BASED_CTLS,
		    adapter->pending_vmcs01_primary) != 0) {
			/*
			 * VMCS02 is already detached, so this cannot remain a
			 * retryable adapter transaction.  Restore the coherent VMCS01
			 * pair before reporting the terminal entry/exit failure.
			 */
			if (vmwrite(VMCS_TSC_OFFSET, old_offset) != 0 ||
			    vmwrite(VMCS_PRI_PROC_BASED_CTLS,
			    (uint32_t)old_primary) != 0)
				panic("%s: cannot roll back VMCS01 TSC state",
				    __func__);
			error = EIO;
		}
		adapter->pending_vmcs01_tsc_offset = 0;
		adapter->pending_vmcs01_primary = 0;
		adapter->pending_vmcs01_tsc = false;
	}
	memset(&adapter->id, 0, sizeof(adapter->id));
	adapter->resource_generation = 0;
	adapter->transaction_active = false;
	if (vmx_nested_vmcs_launch_clear(&adapter->launch) != 0)
		panic("%s: cannot clear VMCS02 launch ownership", __func__);
	return (error);
}

static int
nvmxi_begin(void *arg, const struct vmx_nested_vmcs02_id *id,
    uint64_t resource_generation)
{
	struct vmx_nested_vmcs02_intel *adapter;
	int error;

	adapter = arg;
	if (adapter == NULL || !vmx_nested_vmcs02_id_valid(id) ||
	    resource_generation == 0)
		return (EINVAL);
	error = vmx_nested_vmcs02_intel_inactive_validate(adapter);
	if (error != 0)
		return (error);
	if (vtophys(adapter->vmcs01) == vtophys(adapter->vmcs02) ||
	    curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs01))
		return (EINVAL);

	adapter->vmcs02->identifier = vmx_revision();
	adapter->vmcs02->abort_code = 0;
	error = vmclear(adapter->vmcs02);
	if (error != 0)
		return (EIO);
	error = vmcs_init(adapter->vmcs02);
	if (error != 0) {
		if (vmptrld(adapter->vmcs01) != 0)
			panic("%s: cannot restore VMCS01 after VMCS02 init "
			    "failure", __func__);
		return (EIO);
	}
	error = vmptrld(adapter->vmcs02);
	if (error != 0) {
		if (vmptrld(adapter->vmcs01) != 0)
			panic("%s: cannot restore VMCS01 after VMCS02 load "
			    "failure", __func__);
		return (EIO);
	}
	if (vmx_nested_vmcs_launch_select(&adapter->launch) != 0) {
		if (vmclear(adapter->vmcs02) != 0 ||
		    vmptrld(adapter->vmcs01) != 0)
			panic("%s: cannot restore VMCS01 after launch-state "
			    "failure", __func__);
		return (EIO);
	}
	adapter->transaction_active = true;
	adapter->id = *id;
	adapter->resource_generation = resource_generation;
	return (0);
}

static int
nvmxi_write(void *arg, uint32_t encoding, uint64_t value)
{
	struct vmx_nested_vmcs02_intel *adapter;

	adapter = arg;
	if (adapter == NULL || !adapter->transaction_active ||
	    !adapter->launch.current || curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs02))
		return (EINVAL);
	return (vmwrite(encoding, value) == 0 ? 0 : EIO);
}

static int
nvmxi_commit(void *arg)
{
	struct vmx_nested_vmcs02_intel *adapter;

	adapter = arg;
	if (adapter == NULL || !adapter->transaction_active ||
	    !adapter->launch.current || curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs02))
		return (EINVAL);
	adapter->transaction_active = false;
	return (0);
}

static void
nvmxi_abort(void *arg)
{
	struct vmx_nested_vmcs02_intel *adapter;
	int error;

	adapter = arg;
	if (adapter == NULL || !adapter->transaction_active)
		panic("%s: no active VMCS02 transaction", __func__);
	error = nvmxi_restore_vmcs01(adapter);
	if (error != 0)
		panic("%s: cannot restore VMCS01: %d", __func__, error);
}

static const struct vmx_nested_vmcs02_program_apply_ops nvmxi_ops = {
	.begin = nvmxi_begin,
	.write = nvmxi_write,
	.commit = nvmxi_commit,
	.abort = nvmxi_abort,
};

void
vmx_nested_vmcs02_intel_init(struct vmx_nested_vmcs02_intel *adapter,
    struct vmcs *vmcs01, struct vmcs *vmcs02)
{

	if (adapter == NULL)
		panic("%s: NULL adapter", __func__);
	memset(adapter, 0, sizeof(*adapter));
	adapter->vmcs01 = vmcs01;
	adapter->vmcs02 = vmcs02;
}

const struct vmx_nested_vmcs02_program_apply_ops *
vmx_nested_vmcs02_intel_apply_ops(void)
{

	return (&nvmxi_ops);
}

bool
vmx_nested_vmcs02_intel_vmcs01_current(
    const struct vmx_nested_vmcs02_intel *adapter)
{

	return (adapter != NULL && adapter->vmcs01 != NULL &&
	    curthread->td_critnest != 0 &&
	    nvmxi_current_is(adapter->vmcs01));
}

int
vmx_nested_vmcs02_intel_capture_vmcs01_entry_instruction_length(
    struct vmx_nested_vmcs02_intel *adapter, uint32_t *instruction_length)
{
	uint64_t value;

	if (adapter == NULL || instruction_length == NULL ||
	    adapter->vmcs01 == NULL || adapter->vmcs02 == NULL ||
	    adapter->transaction_active || adapter->launch.current ||
	    curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs01))
		return (EINVAL);
	if (vmread(VMCS_ENTRY_INST_LENGTH, &value) != 0)
		return (EIO);
	if (value > 15)
		return (EINVAL);
	*instruction_length = (uint32_t)value;
	return (0);
}

int
vmx_nested_vmcs02_intel_capture_vmcs01_resources(
    struct vmx_nested_vmcs02_intel *adapter,
    struct vmx_nested_vmcs02_resources *resources)
{
	struct vmx_nested_vmcs02_resources candidate;
	uint64_t secondary, value;
	int error;

	if (adapter == NULL || resources == NULL || adapter->vmcs01 == NULL ||
	    adapter->vmcs02 == NULL || adapter->transaction_active ||
	    adapter->launch.current || curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs01))
		return (EINVAL);

	candidate = *resources;
#define	NVMXI_RESOURCE64(field, encoding) do {				\
	error = vmread((encoding), &candidate.field);			\
	if (error != 0)						\
		return (EIO);						\
} while (0)
#define	NVMXI_RESOURCE32(field, encoding) do {				\
	error = vmread((encoding), &value);				\
	if (error != 0)						\
		return (EIO);						\
	candidate.field = (uint32_t)value;				\
} while (0)
	NVMXI_RESOURCE64(exit_msr_store, VMCS_EXIT_MSR_STORE);
	NVMXI_RESOURCE64(exit_msr_load, VMCS_EXIT_MSR_LOAD);
	NVMXI_RESOURCE64(entry_msr_load, VMCS_ENTRY_MSR_LOAD);
	NVMXI_RESOURCE32(exit_msr_store_count,
	    VMCS_EXIT_MSR_STORE_COUNT);
	NVMXI_RESOURCE32(exit_msr_load_count, VMCS_EXIT_MSR_LOAD_COUNT);
	NVMXI_RESOURCE32(entry_msr_load_count, VMCS_ENTRY_MSR_LOAD_COUNT);
	error = vmread(VMCS_SEC_PROC_BASED_CTLS, &secondary);
	if (error != 0)
		return (EIO);
	if ((secondary & (UINT32_C(1) << 1)) != 0)
		NVMXI_RESOURCE64(eptp01, VMCS_EPTP);
	else
		candidate.eptp01 = 0;
#undef NVMXI_RESOURCE32
#undef NVMXI_RESOURCE64
	*resources = candidate;
	return (0);
}

int
vmx_nested_vmcs02_intel_leave(struct vmx_nested_vmcs02_intel *adapter)
{

	if (adapter == NULL || adapter->transaction_active ||
	    !adapter->launch.current || curthread->td_critnest == 0)
		return (EINVAL);
	return (nvmxi_restore_vmcs01(adapter));
}

int
vmx_nested_vmcs02_intel_entry_instruction(
    const struct vmx_nested_vmcs02_intel *adapter, int *launched)
{

	if (adapter == NULL || launched == NULL ||
	    adapter->transaction_active || !adapter->launch.current ||
	    curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs02))
		return (EINVAL);
	return (vmx_nested_vmcs_launch_instruction(&adapter->launch,
	    launched));
}

/*
 * Synchronize a software-emulated L2 IA32_PAT write with the VMCS02 field
 * which hardware loads on the next nested entry.  This is legal only in the
 * paused-L2 window: VMCS02 is current, L2 still owns the architectural
 * context, and no programming transaction may be active.
 */
int
vmx_nested_vmcs02_intel_write_guest_pat(
    struct vmx_nested_vmcs02_intel *adapter,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation,
    uint64_t value)
{

	if (!nvmxi_exit_capture_valid(adapter, id, resource_generation))
		return (EINVAL);
	return (vmwrite(VMCS_GUEST_IA32_PAT, value) == 0 ? 0 : EIO);
}

/*
 * Apply the hot part of an intercepted L2 IA32_TSC write while VMCS02 is
 * current.  VMCS01 cannot be written until the destructive exit path makes
 * it current, so retain the last coherent L1 offset/control pair for
 * nvmxi_restore_vmcs01().  Repeated writes before that boundary replace the
 * pending pair, just as they replace the current VMCS02 values.
 */
int
vmx_nested_vmcs02_intel_write_tsc(
    struct vmx_nested_vmcs02_intel *adapter,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation,
    uint64_t vmcs02_offset, uint32_t vmcs02_primary, bool timer_enabled,
    uint32_t timer_value, uint64_t vmcs01_offset, uint32_t vmcs01_primary)
{
	uint64_t old_offset, old_primary, old_timer;
	int error;

	if (!nvmxi_exit_capture_valid(adapter, id, resource_generation))
		return (EINVAL);
	if (vmread(VMCS_TSC_OFFSET, &old_offset) != 0 ||
	    vmread(VMCS_PRI_PROC_BASED_CTLS, &old_primary) != 0 ||
	    old_primary > UINT32_MAX)
		return (EIO);
	old_timer = 0;
	if (timer_enabled &&
	    vmread(VMCS_PREEMPTION_TIMER_VALUE, &old_timer) != 0)
		return (EIO);

	error = vmwrite(VMCS_TSC_OFFSET, vmcs02_offset);
	if (error == 0)
		error = vmwrite(VMCS_PRI_PROC_BASED_CTLS, vmcs02_primary);
	if (error == 0 && timer_enabled)
		error = vmwrite(VMCS_PREEMPTION_TIMER_VALUE, timer_value);
	if (error != 0) {
		/*
		 * A failed rollback leaves no trustworthy VMCS02 image.  Do
		 * not return a recoverable error that could resume mixed
		 * clock state.
		 */
		if (vmwrite(VMCS_TSC_OFFSET, old_offset) != 0 ||
		    vmwrite(VMCS_PRI_PROC_BASED_CTLS, old_primary) != 0 ||
		    (timer_enabled &&
		    vmwrite(VMCS_PREEMPTION_TIMER_VALUE, old_timer) != 0))
			panic("%s: cannot roll back VMCS02 TSC state", __func__);
		return (EIO);
	}

	adapter->pending_vmcs01_tsc_offset = vmcs01_offset;
	adapter->pending_vmcs01_primary = vmcs01_primary;
	adapter->pending_vmcs01_tsc = true;
	return (0);
}

int
vmx_nested_vmcs02_intel_commit_entered(
    struct vmx_nested_vmcs02_intel *adapter)
{

	if (adapter == NULL || adapter->transaction_active ||
	    !adapter->launch.current || curthread->td_critnest == 0 ||
	    !nvmxi_current_is(adapter->vmcs02))
		return (EINVAL);
	return (vmx_nested_vmcs_launch_commit_entered(&adapter->launch));
}

int
vmx_nested_vmcs02_intel_peek_exit(
    struct vmx_nested_vmcs02_intel *adapter,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation,
    struct vmx_nested_exit_information *information)
{

	if (information == NULL ||
	    !nvmxi_exit_capture_valid(adapter, id, resource_generation))
		return (EINVAL);
	return (vmx_nested_exit_capture(&nvmxi_exit_capture_ops, adapter,
	    information));
}

static int
nvmxi_capture_runtime(struct vmx_nested_vmcs02_intel *adapter, bool in_smm,
    struct vmx_nested_l2_runtime_state *runtime)
{
	struct vmx_nested_l2_runtime_state candidate;
	uint64_t value;
	u_int i;
	int error;

	memset(&candidate, 0, sizeof(candidate));
#define	NVMXI_RUNTIME64(field, encoding) do {				\
	error = vmread((encoding), &candidate.field);			\
	if (error != 0)						\
		return (EIO);						\
} while (0)
#define	NVMXI_RUNTIME32(field, encoding) do {				\
	error = vmread((encoding), &value);				\
	if (error != 0 || value > UINT32_MAX)				\
		return (EIO);						\
	candidate.field = (uint32_t)value;				\
} while (0)
	NVMXI_RUNTIME64(control.cr0, VMCS_GUEST_CR0);
	NVMXI_RUNTIME64(control.cr3, VMCS_GUEST_CR3);
	NVMXI_RUNTIME64(control.cr4, VMCS_GUEST_CR4);
	NVMXI_RUNTIME64(control.dr7, VMCS_GUEST_DR7);
	NVMXI_RUNTIME32(control.sysenter_cs, VMCS_GUEST_IA32_SYSENTER_CS);
	NVMXI_RUNTIME64(control.sysenter_esp,
	    VMCS_GUEST_IA32_SYSENTER_ESP);
	NVMXI_RUNTIME64(control.sysenter_eip,
	    VMCS_GUEST_IA32_SYSENTER_EIP);
	NVMXI_RUNTIME64(control.pat, VMCS_GUEST_IA32_PAT);
	NVMXI_RUNTIME64(control.efer, VMCS_GUEST_IA32_EFER);
	for (i = 0; i < VMX_NESTED_GUEST_SEGMENT_COUNT; i++) {
		uint32_t encoding;

		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_SELECTOR, &encoding);
		if (error != 0)
			return (error);
		NVMXI_RUNTIME32(arch.segment[i].selector, encoding);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_LIMIT, &encoding);
		if (error != 0)
			return (error);
		NVMXI_RUNTIME32(arch.segment[i].limit, encoding);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_ACCESS, &encoding);
		if (error != 0)
			return (error);
		NVMXI_RUNTIME32(arch.segment[i].access, encoding);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_BASE, &encoding);
		if (error != 0)
			return (error);
		NVMXI_RUNTIME64(arch.segment[i].base, encoding);
	}
	NVMXI_RUNTIME32(arch.gdtr_limit, VMCS_GUEST_GDTR_LIMIT);
	NVMXI_RUNTIME32(arch.idtr_limit, VMCS_GUEST_IDTR_LIMIT);
	NVMXI_RUNTIME64(arch.gdtr_base, VMCS_GUEST_GDTR_BASE);
	NVMXI_RUNTIME64(arch.idtr_base, VMCS_GUEST_IDTR_BASE);
	NVMXI_RUNTIME64(arch.rsp, VMCS_GUEST_RSP);
	NVMXI_RUNTIME64(arch.rip, VMCS_GUEST_RIP);
	NVMXI_RUNTIME64(arch.rflags, VMCS_GUEST_RFLAGS);
	NVMXI_RUNTIME64(arch.pending_debug,
	    VMCS_GUEST_PENDING_DBG_EXCEPTIONS);
	NVMXI_RUNTIME64(arch.debugctl, VMCS_GUEST_IA32_DEBUGCTL);
	NVMXI_RUNTIME32(arch.activity, VMCS_GUEST_ACTIVITY);
	NVMXI_RUNTIME32(arch.interruptibility,
	    VMCS_GUEST_INTERRUPTIBILITY);
	candidate.arch.in_smm = in_smm;
	/*
	 * The VMX-preemption timer residual is defined only while VMCS02
	 * activates the timer, and VMCS02 programs it exclusively on behalf
	 * of L1.  Gate the read on the live pin-based controls so a host
	 * without the feature, or an execution whose L1 left it disabled,
	 * publishes an explicitly invalid capture instead of a stale value.
	 */
	error = vmread(VMCS_PIN_BASED_CTLS, &value);
	if (error != 0)
		return (EIO);
	if ((value & PINBASED_PREMPTION_TIMER) != 0) {
		NVMXI_RUNTIME32(preemption_timer_value,
		    VMCS_PREEMPTION_TIMER_VALUE);
		candidate.preemption_timer_valid = true;
	}
#undef NVMXI_RUNTIME32
#undef NVMXI_RUNTIME64
	*runtime = candidate;
	return (0);
}

int
vmx_nested_vmcs02_intel_capture_exit(
    struct vmx_nested_vmcs02_intel *adapter,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation,
    bool in_smm,
    struct vmx_nested_exit_information *information,
    struct vmx_nested_l2_runtime_state *runtime)
{
	struct vmx_nested_exit_information candidate;
	struct vmx_nested_l2_runtime_state runtime_candidate;
	int error, leave_error;

	if (information == NULL || runtime == NULL ||
	    !nvmxi_exit_capture_valid(adapter, id, resource_generation))
		return (EINVAL);

	error = vmx_nested_exit_capture(&nvmxi_exit_capture_ops, adapter,
	    &candidate);
	if (error != 0)
		goto out;
	error = nvmxi_capture_runtime(adapter, in_smm, &runtime_candidate);
out:
	leave_error = nvmxi_restore_vmcs01(adapter);
	if (leave_error != 0)
		return (leave_error);
	if (error != 0)
		return (EIO);
	*information = candidate;
	*runtime = runtime_candidate;
	return (0);
}

int
vmx_nested_vmcs02_intel_capture_runtime(
    struct vmx_nested_vmcs02_intel *adapter,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation,
    bool in_smm, struct vmx_nested_l2_runtime_state *runtime)
{
	struct vmx_nested_l2_runtime_state candidate;
	int error, leave_error;

	if (runtime == NULL ||
	    !nvmxi_exit_capture_valid(adapter, id, resource_generation))
		return (EINVAL);
	error = nvmxi_capture_runtime(adapter, in_smm, &candidate);
	/*
	 * Capturing a synthetic exit is just as destructive as capturing a
	 * hardware exit: VMCS02 must be cleared and VMCS01 made current on
	 * every path before returning to the outer run loop.
	 */
	leave_error = nvmxi_restore_vmcs01(adapter);
	if (leave_error != 0)
		return (leave_error);
	if (error != 0)
		return (EIO);
	*runtime = candidate;
	return (0);
}

int
vmx_nested_vmcs02_intel_capture_l2(
    struct vmx_nested_vmcs02_intel *adapter,
    const struct vmx_nested_vmcs02_plan *plan, uint64_t resource_generation,
    uint64_t l1_virtual_tsc,
    struct vmx_nested_l2_capture_values *capture,
    bool *rollback_complete)
{
	struct vmx_nested_l2_capture_values candidate;
	uint64_t value;
	int error, leave_error;

	if (rollback_complete == NULL)
		return (EINVAL);
	*rollback_complete = true;
	if (plan == NULL || capture == NULL ||
	    plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY ||
	    !vmx_nested_vmcs02_id_equal(&plan->id, &plan->image.id) ||
	    !nvmxi_exit_capture_valid(adapter, &plan->id,
	    resource_generation))
		return (EINVAL);

	/*
	 * From this point, every path clears VMCS02 and reloads VMCS01.  A
	 * failed capture cannot reconstruct the discarded hot L2 state and
	 * must therefore poison the paired continuation/runtime owner.
	 */
	*rollback_complete = false;
	memset(&candidate, 0, sizeof(candidate));
	error = vmx_nested_exit_capture(&nvmxi_exit_capture_ops, adapter,
	    &candidate.exit);
	if (error != 0)
		goto out;
	error = nvmxi_capture_runtime(adapter, plan->image.l2_arch.in_smm,
	    &candidate.runtime);
	if (error != 0)
		goto out;
#define	NVMXI_L2_READ64(field, encoding) do {				\
	error = vmread((encoding), &candidate.field);			\
	if (error != 0)						\
		goto out;						\
} while (0)
#define	NVMXI_L2_READ32(field, encoding) do {				\
	error = vmread((encoding), &value);				\
	if (error != 0 || value > UINT32_MAX) {			\
		error = EIO;						\
		goto out;						\
	}								\
	candidate.field = (uint32_t)value;				\
} while (0)
	NVMXI_L2_READ32(entry_intr_info, VMCS_ENTRY_INTR_INFO);
	NVMXI_L2_READ32(entry_exception_error,
	    VMCS_ENTRY_EXCEPTION_ERROR);
	NVMXI_L2_READ32(entry_instruction_length,
	    VMCS_ENTRY_INST_LENGTH);
	candidate.pdpte.active = plan->image.pdpte.active;
	if (candidate.pdpte.active) {
		NVMXI_L2_READ64(pdpte.value[0], VMCS_GUEST_PDPTE0);
		NVMXI_L2_READ64(pdpte.value[1], VMCS_GUEST_PDPTE1);
		NVMXI_L2_READ64(pdpte.value[2], VMCS_GUEST_PDPTE2);
		NVMXI_L2_READ64(pdpte.value[3], VMCS_GUEST_PDPTE3);
	}
	candidate.guest_interrupt_status_valid =
	    (plan->image.controls.secondary &
	    NVMXI_VIRTUAL_INTERRUPT_DELIVERY) != 0;
	if (candidate.guest_interrupt_status_valid) {
		error = vmread(VMCS_GUEST_INTR_STATUS, &value);
		if (error != 0 || value > UINT16_MAX) {
			error = EIO;
			goto out;
		}
		candidate.guest_interrupt_status = (uint16_t)value;
	}
	if (plan->image.preemption_timer_enabled) {
		error = vmread(VMCS_PREEMPTION_TIMER_VALUE, &value);
		if (error != 0 || value > UINT32_MAX) {
			error = EIO;
			goto out;
		}
		error = vmx_nested_timer_start(l1_virtual_tsc,
		    plan->image.preemption_timer_rate, (uint32_t)value,
		    &candidate.preemption_timer);
		if (error != 0)
			goto out;
	}
	error = 0;
out:
#undef NVMXI_L2_READ32
#undef NVMXI_L2_READ64
	leave_error = nvmxi_restore_vmcs01(adapter);
	if (leave_error != 0)
		return (leave_error);
	if (error != 0)
		return (error == EINVAL ? EINVAL : EIO);
	*capture = candidate;
	*rollback_complete = true;
	return (0);
}
