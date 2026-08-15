/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_entry_environment.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_l2_rebuild.h"
#include "vmx_nested_link.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs12.h"
#include "vmx_nested_vmcs02.h"
#include "vmx_nested_vmentry.h"

int
vmx_nested_l2_rebuild_plan(
    const struct vmx_nested_vmcs12_snapshot *snapshot,
    const struct vmx_nested_entry_environment *environment,
    const struct vmx_nested_l2_portable_state *portable,
    bool shadow_restored, struct vmx_nested_vmcs02_plan *plan)
{
	struct vmx_nested_vmcs12_snapshot resume;
	struct vmx_nested_vmcs02_input input;
	struct vmx_nested_vmcs02_plan basis, candidate;
	struct vmx_nested_vmentry_input vmentry;
	uint64_t signature;
	bool linked_state;
	int error;

	if (snapshot == NULL || environment == NULL || portable == NULL ||
	    plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), snapshot,
	    sizeof(*snapshot)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), environment,
	    sizeof(*environment)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), portable,
	    sizeof(*portable)))
		return (EINVAL);
	error = vmx_nested_vmcs12_snapshot_validate(snapshot);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_environment_validate(environment);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_portable_validate(portable);
	if (error != 0)
		return (error);
	error = vmx_nested_capabilities_signature(&snapshot->capabilities,
	    &signature);
	if (error != 0)
		return (error);
	linked_state = vmx_nested_link_state_required(
	    snapshot->controls.primary, snapshot->controls.secondary,
	    snapshot->controls.vmentry, snapshot->controls.in_smm,
	    snapshot->guest_arch.in_smm, snapshot->link_pointer);
	if (signature != portable->capability_signature ||
	    snapshot->capability_signature != signature ||
	    !snapshot->launched ||
	    snapshot->launch_epoch != portable->id.execution_epoch ||
	    snapshot->vmcs12_gpa != portable->id.vmcs12_gpa ||
	    !vmx_nested_vmcs02_id_equal(&environment->id, &portable->id) ||
	    environment->capability_signature != signature ||
	    linked_state != shadow_restored)
		return (ESTALE);

	/*
	 * Validate and compose from the post-entry architectural L2 image.
	 * Entry-only sources were consumed before the source VM entered L2:
	 * any linked state required by shadowing or SMM has been restored
	 * separately, PDPTEs come from the portable image, and the entry MSR
	 * list's resulting values are in portable->software_msrs and runtime
	 * control/architectural state.
	 */
	resume = *snapshot;
	resume.guest_control = portable->runtime.control;
	resume.guest_arch = portable->runtime.arch;
	for (uint32_t i = 0; i < 4; i++)
		resume.pdpte[i] = portable->pdpte.value[i];
	resume.controls.entry_intr_info = portable->entry_intr_info;
	resume.controls.entry_exception_error =
	    portable->entry_exception_error;
	resume.controls.entry_instruction_length =
	    portable->entry_instruction_length;
	resume.controls.entry_msr_load_address = 0;
	resume.controls.entry_msr_load_count = 0;
	resume.link_pointer = UINT64_MAX;
	resume.executive_vmcs = 0;
	resume.executive_vmcs_valid = false;
	error = vmx_nested_vmcs12_vmentry_input(&resume, NULL, NULL,
	    &vmentry);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_environment_bind(environment, &portable->id,
	    &snapshot->capabilities, &vmentry, &input);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_prepare(&input, &basis);
	if (error != 0)
		return (error);
	if (basis.vmentry.disposition != VMX_NESTED_VMENTRY_READY)
		return (EPROTO);
	error = vmx_nested_l2_portable_apply(portable,
	    &snapshot->capabilities, &basis, &candidate);
	if (error != 0)
		return (error);
	/*
	 * VM-exit save controls require the original VMCS12 values, not the
	 * post-entry live L2 values used to validate the resumed execution.
	 */
	candidate.image.vmcs12_control = snapshot->guest_control;
	candidate.image.vmcs12_arch = snapshot->guest_arch;
	candidate.image.vmcs12_entry_intr_info =
	    snapshot->controls.entry_intr_info;
	*plan = candidate;
	return (0);
}
