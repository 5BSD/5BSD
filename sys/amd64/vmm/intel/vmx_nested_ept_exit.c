/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_ept_exit.h"
#include "vmx_nested_ept_reflect.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_ept_exit_prepare(const struct vmx_nested_vmcs02_image *image,
    const struct vmx_nested_l2_runtime_state *runtime,
    const struct vmx_nested_ept_handoff_result *fault,
    struct vmx_nested_ept_exit_plan *plan)
{
	struct vmx_nested_vmexit_state_input state_input;
	struct vmx_nested_ept_exit_plan candidate;
	int error;

	if (image == NULL || runtime == NULL || fault == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), image,
	    sizeof(*image)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), fault,
	    sizeof(*fault)) ||
	    !vmx_nested_vmcs02_id_valid(&image->id) ||
	    fault->id.vmcs_generation != image->id.state_generation ||
	    fault->id.execution_epoch != image->id.execution_epoch)
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.id = image->id;
	error = vmx_nested_ept_reflection_information(fault,
	    &fault->vmcs02_exit,
	    &candidate.exit_information);
	if (error != 0)
		return (error);

	memset(&state_input, 0, sizeof(state_input));
	state_input.l1_host = &image->l1_host;
	state_input.l2_runtime = runtime;
	state_input.vmcs12_control = &image->vmcs12_control;
	state_input.vmcs12_arch = &image->vmcs12_arch;
	state_input.vmexit = image->vmcs12_vmexit;
	state_input.vmcs12_vmentry = image->vmcs12_vmentry;
	state_input.vmcs12_entry_intr_info =
	    image->vmcs12_entry_intr_info;
	state_input.save_guest_lma = image->save_guest_lma;
	error = vmx_nested_vmexit_state_prepare(&state_input,
	    &candidate.state);
	if (error != 0)
		return (error);

	*plan = candidate;
	return (0);
}
