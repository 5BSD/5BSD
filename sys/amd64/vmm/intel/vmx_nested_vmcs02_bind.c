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

#include "vmx_nested_vmcs02_bind.h"
#include "vmx_nested_state_range.h"

#define	NVMXB_PIN_POSTED_INTERRUPT	(UINT32_C(1) << 7)
#define	NVMXB_PIN_PREEMPTION_TIMER	(UINT32_C(1) << 6)
#define	NVMXB_PRIMARY_TPR_SHADOW	(UINT32_C(1) << 21)
#define	NVMXB_PRIMARY_IO_BITMAPS	(UINT32_C(1) << 25)
#define	NVMXB_PRIMARY_MSR_BITMAPS	(UINT32_C(1) << 28)
#define	NVMXB_SECONDARY_APIC_ACCESS	(UINT32_C(1) << 0)
#define	NVMXB_SECONDARY_EPT		(UINT32_C(1) << 1)
#define	NVMXB_SECONDARY_VPID		(UINT32_C(1) << 5)
#define	NVMXB_SECONDARY_TSC_SCALING	(UINT32_C(1) << 25)

static bool
nvmxb_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (vmx_nested_vmcs02_id_equal(a, b));
}

static bool
nvmxb_address_valid(uint64_t address, uint64_t alignment)
{

	return (address != UINT64_MAX && (address & (alignment - 1)) == 0);
}

static bool
nvmxb_msr_area_valid(uint64_t address, uint32_t count)
{
	uint64_t length;

	if (count == 0)
		return (true);
	if (!nvmxb_address_valid(address, 16))
		return (false);
	length = (uint64_t)count * 16;
	return (address <= UINT64_MAX - (length - 1));
}

static bool
nvmxb_eptp_structurally_valid(uint64_t eptp)
{
	uint64_t memory_type;
	uint32_t walk_length;

	if (eptp == UINT64_MAX || (eptp & UINT64_C(0xf80)) != 0)
		return (false);
	memory_type = eptp & 7;
	walk_length = (eptp >> 3) & 7;
	return ((memory_type == 0 || memory_type == 6) &&
	    (walk_length == 3 || walk_length == 4));
}

int
vmx_nested_vmcs02_bind(const struct vmx_nested_vmcs02_image *image,
    const struct vmx_nested_host_state *l0_host,
    const struct vmx_nested_vmcs02_resources *resources,
    struct vmx_nested_vmcs02_hardware_plan *plan)
{
	struct vmx_nested_vmcs02_hardware_plan candidate;

	if (image == NULL || l0_host == NULL || resources == NULL ||
	    plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), image,
	    sizeof(*image)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), l0_host,
	    sizeof(*l0_host)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), resources,
	    sizeof(*resources)) ||
	    !vmx_nested_vmcs02_id_valid(&image->id) ||
	    !vmx_nested_vmcs02_id_valid(&resources->id) ||
	    resources->resource_generation == 0 ||
	    !nvmxb_id_equal(&image->id, &resources->id) ||
	    (image->controls.secondary & NVMXB_SECONDARY_EPT) == 0 ||
	    image->preemption_timer_enabled !=
	    ((image->controls.pinbased &
	    NVMXB_PIN_PREEMPTION_TIMER) != 0) ||
	    vmx_nested_timer_state_validate(&image->preemption_timer,
	    image->preemption_timer_enabled) != 0 ||
	    (image->preemption_timer_enabled &&
	    (!image->preemption_timer.armed ||
	    image->preemption_timer_rate > 31)) ||
	    (!image->preemption_timer_enabled &&
	    (image->preemption_timer.armed ||
	    image->preemption_timer_rate != 0)) ||
	    image->tsc.vmcs02_scaling_enabled !=
	    ((image->controls.secondary &
	    NVMXB_SECONDARY_TSC_SCALING) != 0) ||
	    ((image->controls.secondary & NVMXB_SECONDARY_VPID) != 0 &&
	    image->vpid.hardware_vpid == 0))
		return (EINVAL);

	if (((image->controls.primary & NVMXB_PRIMARY_IO_BITMAPS) != 0 &&
	    (!nvmxb_address_valid(resources->io_bitmap_a, 4096) ||
	    !nvmxb_address_valid(resources->io_bitmap_b, 4096))) ||
	    ((image->controls.primary & NVMXB_PRIMARY_MSR_BITMAPS) != 0 &&
	    !nvmxb_address_valid(resources->msr_bitmap, 4096)) ||
	    ((image->controls.primary & NVMXB_PRIMARY_TPR_SHADOW) != 0 &&
	    !nvmxb_address_valid(resources->virtual_apic, 4096)) ||
	    ((image->controls.secondary & NVMXB_SECONDARY_APIC_ACCESS) != 0 &&
	    !nvmxb_address_valid(resources->apic_access, 4096)) ||
	    ((image->controls.pinbased & NVMXB_PIN_POSTED_INTERRUPT) != 0 &&
	    !nvmxb_address_valid(resources->posted_interrupt_descriptor, 64)) ||
	    !nvmxb_msr_area_valid(resources->exit_msr_store,
	    resources->exit_msr_store_count) ||
	    !nvmxb_msr_area_valid(resources->exit_msr_load,
	    resources->exit_msr_load_count) ||
	    !nvmxb_msr_area_valid(resources->entry_msr_load,
	    resources->entry_msr_load_count))
		return (EINVAL);
	if (image->ept_enabled &&
	    (resources->ept_capability_signature == 0 ||
	    resources->ept_capability_signature !=
	    image->ept.capability_signature ||
	    !nvmxb_eptp_structurally_valid(resources->eptp02) ||
	    !nvmxb_address_valid(resources->eptp02 & ~UINT64_C(0xfff),
	    4096)))
		return (ESTALE);
	if (!image->ept_enabled &&
	    (resources->ept_capability_signature != 0 ||
	    resources->eptp02 != 0 ||
	    !nvmxb_eptp_structurally_valid(resources->eptp01) ||
	    !nvmxb_address_valid(resources->eptp01 & ~UINT64_C(0xfff),
	    4096)))
		return (ESTALE);

	memset(&candidate, 0, sizeof(candidate));
	candidate.id = image->id;
	candidate.resource_generation = resources->resource_generation;
	candidate.controls = image->controls;
	candidate.execution = image->execution.state;
	candidate.host = *l0_host;
	candidate.guest_control = image->l2_control;
	candidate.guest_arch = image->l2_arch;
	candidate.pdpte = image->pdpte;
	candidate.tsc_offset = image->tsc.vmcs02_offset;
	candidate.tsc_multiplier = image->tsc.vmcs02_multiplier;
	candidate.eptp = image->ept_enabled ? resources->eptp02 :
	    resources->eptp01;
	candidate.io_bitmap_a = resources->io_bitmap_a;
	candidate.io_bitmap_b = resources->io_bitmap_b;
	candidate.msr_bitmap = resources->msr_bitmap;
	candidate.virtual_apic = resources->virtual_apic;
	candidate.apic_access = resources->apic_access;
	candidate.posted_interrupt_descriptor =
	    resources->posted_interrupt_descriptor;
	candidate.exit_msr_store = resources->exit_msr_store;
	candidate.exit_msr_load = resources->exit_msr_load;
	candidate.entry_msr_load = resources->entry_msr_load;
	candidate.exit_msr_store_count = resources->exit_msr_store_count;
	candidate.exit_msr_load_count = resources->exit_msr_load_count;
	candidate.entry_msr_load_count = resources->entry_msr_load_count;
	candidate.entry_intr_info = image->entry_intr_info;
	candidate.entry_exception_error = image->entry_exception_error;
	candidate.entry_instruction_length =
	    image->entry_instruction_length;
	candidate.tpr_threshold = image->tpr_threshold;
	candidate.cr3_target_count = image->cr3_target_count;
	candidate.preemption_timer_value = image->preemption_timer.remaining;
	candidate.vpid = image->vpid.hardware_vpid;
	candidate.posted_interrupt_vector =
	    image->posted_interrupt_vector;
	candidate.ept_enabled = true;
	candidate.preemption_timer_enabled =
	    image->preemption_timer_enabled;
	candidate.tsc_scaling_enabled = image->tsc.vmcs02_scaling_enabled;
	*plan = candidate;
	return (0);
}
