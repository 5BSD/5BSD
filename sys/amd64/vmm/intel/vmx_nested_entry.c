/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_validate.h"

#define	NVMX_PIN_EXTINT_EXITING		(UINT32_C(1) << 0)
#define	NVMX_PIN_NMI_EXITING		(UINT32_C(1) << 3)
#define	NVMX_PIN_VIRTUAL_NMI		(UINT32_C(1) << 5)
#define	NVMX_PIN_PREEMPTION_TIMER	(UINT32_C(1) << 6)
#define	NVMX_PIN_POSTED_INTERRUPT	(UINT32_C(1) << 7)

#define	NVMX_PRIMARY_NMI_WINDOW		(UINT32_C(1) << 22)
#define	NVMX_PRIMARY_TPR_SHADOW		(UINT32_C(1) << 21)
#define	NVMX_PRIMARY_IO_BITMAPS		(UINT32_C(1) << 25)
#define	NVMX_PRIMARY_MTF		(UINT32_C(1) << 27)
#define	NVMX_PRIMARY_MSR_BITMAPS	(UINT32_C(1) << 28)
#define	NVMX_PRIMARY_SECONDARY		(UINT32_C(1) << 31)

#define	NVMX_SECONDARY_APIC_ACCESS	(UINT32_C(1) << 0)
#define	NVMX_SECONDARY_EPT		(UINT32_C(1) << 1)
#define	NVMX_SECONDARY_X2APIC		(UINT32_C(1) << 4)
#define	NVMX_SECONDARY_VPID		(UINT32_C(1) << 5)
#define	NVMX_SECONDARY_UNRESTRICTED	(UINT32_C(1) << 7)
#define	NVMX_SECONDARY_APIC_REG		(UINT32_C(1) << 8)
#define	NVMX_SECONDARY_VINT_DELIVERY	(UINT32_C(1) << 9)
#define	NVMX_SECONDARY_TSC_SCALING	(UINT32_C(1) << 25)

#define	NVMX_EXIT_ACK_INTERRUPT		(UINT32_C(1) << 15)
#define	NVMX_EXIT_SAVE_PREEMPT_TIMER	(UINT32_C(1) << 22)

#define	NVMX_ENTRY_SMM			(UINT32_C(1) << 10)
#define	NVMX_ENTRY_DUAL_MONITOR		(UINT32_C(1) << 11)

#define	NVMX_INTR_VALID			(UINT32_C(1) << 31)
#define	NVMX_INTR_DELIVER_ERROR		(UINT32_C(1) << 11)
#define	NVMX_INTR_RESERVED		UINT32_C(0x7ffff000)
#define	NVMX_INTR_TYPE_SHIFT		8
#define	NVMX_INTR_TYPE_MASK		7
#define	NVMX_INTR_TYPE_NMI		2
#define	NVMX_INTR_TYPE_HW_EXCEPTION	3
#define	NVMX_INTR_TYPE_SW_INTERRUPT	4
#define	NVMX_INTR_TYPE_PRIV_SW_EXCEPTION	5
#define	NVMX_INTR_TYPE_SW_EXCEPTION	6
#define	NVMX_INTR_TYPE_OTHER		7

#define	NVMX_EPT_CAP_WALK_4		(UINT64_C(1) << 6)
#define	NVMX_EPT_CAP_WALK_5		(UINT64_C(1) << 7)
#define	NVMX_EPT_CAP_MEMORY_UC		(UINT64_C(1) << 8)
#define	NVMX_EPT_CAP_MEMORY_WB		(UINT64_C(1) << 14)
#define	NVMX_EPT_CAP_AD			(UINT64_C(1) << 21)

static int
nvmx_entry_fail(enum vmx_nested_entry_control_failure failure,
    enum vmx_nested_entry_control_failure *reported)
{

	if (reported != NULL)
		*reported = failure;
	return (EINVAL);
}

static bool
nvmx_msr_area_valid(const struct vmx_nested_capabilities *capabilities,
    uint64_t address, uint32_t count)
{
	uint64_t length;
	uint32_t maximum;

	if (count == 0)
		return (true);
	maximum = 512U * (1U + ((capabilities->misc >> 25) & 7));
	if (count > maximum)
		return (false);
	length = (uint64_t)count * 16;
	return (vmx_nested_vmx_physical_range_valid(capabilities, address,
	    length, 16));
}

static bool
nvmx_exception_has_error(uint32_t vector)
{

	return (vector == 8 || (vector >= 10 && vector <= 14) ||
	    vector == 17);
}

static bool
nvmx_event_valid(const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_entry_controls *controls, uint32_t secondary,
    uint64_t guest_cr0)
{
	uint32_t info, type, vector;
	bool deliver_error, error_required, length_required;

	info = controls->entry_intr_info;
	if ((info & NVMX_INTR_VALID) == 0)
		return (true);
	if ((info & NVMX_INTR_RESERVED) != 0)
		return (false);
	type = (info >> NVMX_INTR_TYPE_SHIFT) & NVMX_INTR_TYPE_MASK;
	vector = info & 0xff;
	if (type == 1 ||
	    (type == NVMX_INTR_TYPE_OTHER &&
	    (((uint32_t)(capabilities->primary >> 32) &
	    NVMX_PRIMARY_MTF) == 0 || vector != 0)) ||
	    (type == NVMX_INTR_TYPE_NMI && vector != 2) ||
	    (type == NVMX_INTR_TYPE_HW_EXCEPTION && vector > 31) ||
	    (type == NVMX_INTR_TYPE_PRIV_SW_EXCEPTION && vector != 1) ||
	    (type == NVMX_INTR_TYPE_SW_EXCEPTION &&
	    vector != 3 && vector != 4) ||
	    type > NVMX_INTR_TYPE_OTHER)
		return (false);
	deliver_error = (info & NVMX_INTR_DELIVER_ERROR) != 0;
	error_required = type == NVMX_INTR_TYPE_HW_EXCEPTION &&
	    !((secondary & NVMX_SECONDARY_UNRESTRICTED) != 0 &&
	    (guest_cr0 & 1) == 0) &&
	    nvmx_exception_has_error(vector);
	if (deliver_error != error_required ||
	    (deliver_error && (controls->entry_exception_error >> 16) != 0))
		return (false);
	length_required = type == NVMX_INTR_TYPE_SW_INTERRUPT ||
	    type == NVMX_INTR_TYPE_PRIV_SW_EXCEPTION ||
	    type == NVMX_INTR_TYPE_SW_EXCEPTION;
	if (length_required &&
	    (controls->entry_instruction_length > 15 ||
	    (controls->entry_instruction_length == 0 &&
	    (capabilities->misc & (UINT64_C(1) << 30)) == 0)))
		return (false);
	return (true);
}

bool
vmx_nested_eptp_valid(const struct vmx_nested_capabilities *capabilities,
    uint64_t eptp)
{
	uint64_t address, memory_type;
	uint32_t walk_length;

	memory_type = eptp & 7;
	if ((memory_type == 0 &&
	    (capabilities->ept_vpid & NVMX_EPT_CAP_MEMORY_UC) == 0) ||
	    (memory_type == 6 &&
	    (capabilities->ept_vpid & NVMX_EPT_CAP_MEMORY_WB) == 0) ||
	    (memory_type != 0 && memory_type != 6))
		return (false);
	walk_length = (eptp >> 3) & 7;
	if ((walk_length == 3 &&
	    (capabilities->ept_vpid & NVMX_EPT_CAP_WALK_4) == 0) ||
	    (walk_length == 4 &&
	    (capabilities->ept_vpid & NVMX_EPT_CAP_WALK_5) == 0) ||
	    (walk_length != 3 && walk_length != 4) ||
	    ((eptp & (UINT64_C(1) << 6)) != 0 &&
	    (capabilities->ept_vpid & NVMX_EPT_CAP_AD) == 0) ||
	    (eptp & UINT64_C(0xf80)) != 0)
		return (false);
	address = eptp & ~UINT64_C(0xfff);
	return (vmx_nested_vmx_physical_range_valid(capabilities, address,
	    4096, 4096));
}

int
vmx_nested_entry_controls_validate_for_guest(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_entry_controls *controls,
    uint64_t guest_cr0,
    enum vmx_nested_entry_control_failure *failure)
{
	uint32_t secondary;

	if (failure != NULL)
		*failure = VMX_NESTED_ENTRY_CONTROL_OK;
	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    controls == NULL)
		return (EINVAL);
	if (!vmx_nested_control_valid(controls->pinbased,
	    capabilities->pinbased) ||
	    !vmx_nested_control_valid(controls->primary,
	    capabilities->primary))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_EXECUTION_CONTROLS,
		    failure));
	secondary = (controls->primary & NVMX_PRIMARY_SECONDARY) != 0 ?
	    controls->secondary : 0;
	if ((controls->primary & NVMX_PRIMARY_SECONDARY) != 0 &&
	    !vmx_nested_control_valid(secondary, capabilities->secondary))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_EXECUTION_CONTROLS,
		    failure));
	if (controls->cr3_target_count >
	    ((capabilities->misc >> 16) & UINT64_C(0x1ff)))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_CR3_TARGET_COUNT,
		    failure));
	if (((controls->primary & NVMX_PRIMARY_IO_BITMAPS) != 0 &&
	    (!vmx_nested_vmx_physical_range_valid(capabilities,
	    controls->io_bitmap_a,
	    4096, 4096) ||
	    !vmx_nested_vmx_physical_range_valid(capabilities,
	    controls->io_bitmap_b,
	    4096, 4096))) ||
	    ((controls->primary & NVMX_PRIMARY_MSR_BITMAPS) != 0 &&
	    !vmx_nested_vmx_physical_range_valid(capabilities,
	    controls->msr_bitmap,
	    4096, 4096)) ||
	    ((controls->primary & NVMX_PRIMARY_TPR_SHADOW) != 0 &&
	    !vmx_nested_vmx_physical_range_valid(capabilities,
	    controls->virtual_apic,
	    4096, 4096)) ||
	    ((secondary & NVMX_SECONDARY_APIC_ACCESS) != 0 &&
	    !vmx_nested_vmx_physical_range_valid(capabilities,
	    controls->apic_access,
	    4096, 4096)))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_CONTROL_ADDRESS,
		    failure));
	if ((controls->primary & NVMX_PRIMARY_TPR_SHADOW) != 0 &&
	    (secondary & NVMX_SECONDARY_VINT_DELIVERY) == 0 &&
	    (controls->tpr_threshold & ~UINT32_C(0xf)) != 0)
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_TPR_DEPENDENCY,
		    failure));
	if (((controls->pinbased & NVMX_PIN_NMI_EXITING) == 0 &&
	    (controls->pinbased & NVMX_PIN_VIRTUAL_NMI) != 0) ||
	    ((controls->pinbased & NVMX_PIN_VIRTUAL_NMI) == 0 &&
	    (controls->primary & NVMX_PRIMARY_NMI_WINDOW) != 0))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_NMI_DEPENDENCY,
		    failure));
	if (((controls->primary & NVMX_PRIMARY_TPR_SHADOW) == 0 &&
	    (secondary & (NVMX_SECONDARY_X2APIC |
	    NVMX_SECONDARY_APIC_REG | NVMX_SECONDARY_VINT_DELIVERY)) != 0) ||
	    ((secondary & NVMX_SECONDARY_X2APIC) != 0 &&
	    (secondary & NVMX_SECONDARY_APIC_ACCESS) != 0) ||
	    ((secondary & NVMX_SECONDARY_VINT_DELIVERY) != 0 &&
	    (controls->pinbased & NVMX_PIN_EXTINT_EXITING) == 0))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_APIC_DEPENDENCY,
		    failure));
	if ((controls->pinbased & NVMX_PIN_POSTED_INTERRUPT) != 0 &&
	    ((secondary & NVMX_SECONDARY_VINT_DELIVERY) == 0 ||
	    (controls->vmexit & NVMX_EXIT_ACK_INTERRUPT) == 0 ||
	    controls->posted_interrupt_vector > 255 ||
	    !vmx_nested_vmx_physical_range_valid(capabilities,
	    controls->posted_interrupt_descriptor, 64, 64)))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_POSTED_INTERRUPT,
		    failure));
	if ((secondary & NVMX_SECONDARY_VPID) != 0 && controls->vpid == 0)
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_VPID, failure));
	if ((secondary & NVMX_SECONDARY_UNRESTRICTED) != 0 &&
	    (secondary & NVMX_SECONDARY_EPT) == 0)
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_EPT_DEPENDENCY,
		    failure));
	if ((secondary & NVMX_SECONDARY_EPT) != 0 &&
	    !vmx_nested_eptp_valid(capabilities, controls->eptp))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_EPTP, failure));
	/* Intel SDM 29.2.1.1: a scaling factor of zero is invalid. */
	if ((secondary & NVMX_SECONDARY_TSC_SCALING) != 0 &&
	    controls->tsc_multiplier == 0)
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_TSC_MULTIPLIER,
		    failure));
	if (!vmx_nested_control_valid(controls->vmexit,
	    capabilities->vmexit) ||
	    ((controls->vmexit & NVMX_EXIT_SAVE_PREEMPT_TIMER) != 0 &&
	    (controls->pinbased & NVMX_PIN_PREEMPTION_TIMER) == 0))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_EXIT_CONTROLS,
		    failure));
	if (!nvmx_msr_area_valid(capabilities,
	    controls->exit_msr_store_address, controls->exit_msr_store_count) ||
	    !nvmx_msr_area_valid(capabilities,
	    controls->exit_msr_load_address, controls->exit_msr_load_count) ||
	    !nvmx_msr_area_valid(capabilities,
	    controls->entry_msr_load_address, controls->entry_msr_load_count))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_MSR_AREA, failure));
	if (!vmx_nested_control_valid(controls->vmentry,
	    capabilities->vmentry))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_ENTRY_CONTROLS,
		    failure));
	if (!nvmx_event_valid(capabilities, controls, secondary, guest_cr0))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_EVENT_INJECTION,
		    failure));
	if ((!controls->in_smm &&
	    (controls->vmentry & (NVMX_ENTRY_SMM |
	    NVMX_ENTRY_DUAL_MONITOR)) != 0) ||
	    (controls->vmentry & (NVMX_ENTRY_SMM |
	    NVMX_ENTRY_DUAL_MONITOR)) ==
	    (NVMX_ENTRY_SMM | NVMX_ENTRY_DUAL_MONITOR))
		return (nvmx_entry_fail(VMX_NESTED_ENTRY_SMM_CONTROLS,
		    failure));
	return (0);
}

int
vmx_nested_entry_controls_validate(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_entry_controls *controls,
    enum vmx_nested_entry_control_failure *failure)
{

	return (vmx_nested_entry_controls_validate_for_guest(capabilities,
	    controls, 0, failure));
}
