/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/systm.h>

#include <machine/cpufunc.h>
#include <machine/specialreg.h>

#include "vmx_nested_control_capabilities.h"
#include "vmx_nested_control_capabilities_intel.h"

int
vmx_nested_control_capabilities_intel_read(
    struct vmx_nested_vmcs02_capabilities *capabilities)
{
	struct vmx_nested_control_capabilities_raw raw;
	uint64_t selected_primary;
	bool true_controls;

	if (capabilities == NULL)
		return (EINVAL);
	memset(&raw, 0, sizeof(raw));
	raw.basic = rdmsr(MSR_VMX_BASIC);
	raw.legacy_pinbased = rdmsr(MSR_VMX_PINBASED_CTLS);
	raw.legacy_primary = rdmsr(MSR_VMX_PROCBASED_CTLS);
	raw.legacy_vmexit = rdmsr(MSR_VMX_EXIT_CTLS);
	raw.legacy_vmentry = rdmsr(MSR_VMX_ENTRY_CTLS);
	true_controls = (raw.basic & (UINT64_C(1) << 55)) != 0;
	if (true_controls) {
		raw.true_pinbased = rdmsr(MSR_VMX_TRUE_PINBASED_CTLS);
		raw.true_primary = rdmsr(MSR_VMX_TRUE_PROCBASED_CTLS);
		raw.true_vmexit = rdmsr(MSR_VMX_TRUE_EXIT_CTLS);
		raw.true_vmentry = rdmsr(MSR_VMX_TRUE_ENTRY_CTLS);
	}
	selected_primary = true_controls ? raw.true_primary :
	    raw.legacy_primary;
	if (((uint32_t)(selected_primary >> 32) &
	    (UINT32_C(1) << 31)) != 0)
		raw.secondary = rdmsr(MSR_VMX_PROCBASED_CTLS2);
	return (vmx_nested_control_capabilities_select(&raw, capabilities));
}
