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
#include "vmx_nested_guest.h"
#include "vmx_nested_msr_state.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_tsc_aux.h"
#include "vmx_nested_validate.h"

#define	NVMXS_MSR_SYSENTER_CS	0x00000174U
#define	NVMXS_MSR_SYSENTER_ESP	0x00000175U
#define	NVMXS_MSR_SYSENTER_EIP	0x00000176U
#define	NVMXS_MSR_DEBUGCTL	0x000001d9U
#define	NVMXS_MSR_PAT		0x00000277U
#define	NVMXS_MSR_EFER		0xc0000080U
#define	NVMXS_MSR_STAR		0xc0000081U
#define	NVMXS_MSR_LSTAR		0xc0000082U
#define	NVMXS_MSR_CSTAR		0xc0000083U
#define	NVMXS_MSR_SFMASK	0xc0000084U
#define	NVMXS_MSR_FS_BASE	0xc0000100U
#define	NVMXS_MSR_GS_BASE	0xc0000101U
#define	NVMXS_MSR_KGSBASE	0xc0000102U
#define	NVMXS_MSR_TSC_AUX	0xc0000103U

#define	NVMXS_CR0_PG		(1ULL << 31)
#define	NVMXS_EFER_LME		(1ULL << 8)
#define	NVMXS_EFER_LMA		(1ULL << 10)
#define	NVMXS_EFER_VALID	((1ULL << 0) | NVMXS_EFER_LME | \
	    NVMXS_EFER_LMA | (1ULL << 11))

int
vmx_nested_software_msr_list(
    const struct vmx_nested_software_msrs *software, bool tsc_aux_available,
    struct vmx_nested_msr_entry *entries, uint32_t capacity, uint32_t *count)
{
	size_t entries_size;
	uint32_t required;

	if (software == NULL || entries == NULL || count == NULL)
		return (EINVAL);
#if SIZE_MAX <= UINT32_MAX
	if (capacity > SIZE_MAX / sizeof(*entries))
		return (EOVERFLOW);
#endif
	entries_size = (size_t)capacity * sizeof(*entries);
	if (vmx_nested_state_ranges_overlap(entries, entries_size, software,
	    sizeof(*software)) ||
	    vmx_nested_state_ranges_overlap(count, sizeof(*count), software,
	    sizeof(*software)) ||
	    vmx_nested_state_ranges_overlap(count, sizeof(*count), entries,
	    entries_size))
		return (EINVAL);
	required = VMX_NESTED_SOFTWARE_MSR_COUNT -
	    (tsc_aux_available ? 0U : 1U);
	if (capacity < required)
		return (ENOSPC);
	entries[0] = (struct vmx_nested_msr_entry){
		.index = NVMXS_MSR_STAR, .value = software->star,
	};
	entries[1] = (struct vmx_nested_msr_entry){
		.index = NVMXS_MSR_LSTAR, .value = software->lstar,
	};
	entries[2] = (struct vmx_nested_msr_entry){
		.index = NVMXS_MSR_CSTAR, .value = software->cstar,
	};
	entries[3] = (struct vmx_nested_msr_entry){
		.index = NVMXS_MSR_SFMASK, .value = software->sfmask,
	};
	entries[4] = (struct vmx_nested_msr_entry){
		.index = NVMXS_MSR_KGSBASE, .value = software->kgsbase,
	};
	if (tsc_aux_available) {
		entries[5] = (struct vmx_nested_msr_entry){
			.index = NVMXS_MSR_TSC_AUX,
			.value = software->tsc_aux,
		};
	}
	*count = required;
	return (0);
}

int
vmx_nested_software_msr_capture(bool tsc_aux_available,
    const struct vmx_nested_msr_apply_ops *ops, void *arg,
    struct vmx_nested_software_msrs *software)
{
	struct vmx_nested_msr_apply_ops ops_snapshot;
	struct vmx_nested_software_msrs candidate;
	uint64_t *values[VMX_NESTED_SOFTWARE_MSR_COUNT];
	uint32_t indices[VMX_NESTED_SOFTWARE_MSR_COUNT];
	uint32_t count;
	int error;

	if (ops == NULL || ops->read == NULL || software == NULL ||
	    vmx_nested_state_ranges_overlap(software, sizeof(*software), ops,
	    sizeof(*ops)))
		return (EINVAL);
	/* Keep every field read bound to one private adapter transaction. */
	ops_snapshot = *ops;
	memset(&candidate, 0, sizeof(candidate));
	indices[0] = NVMXS_MSR_STAR;
	indices[1] = NVMXS_MSR_LSTAR;
	indices[2] = NVMXS_MSR_CSTAR;
	indices[3] = NVMXS_MSR_SFMASK;
	indices[4] = NVMXS_MSR_KGSBASE;
	indices[5] = NVMXS_MSR_TSC_AUX;
	values[0] = &candidate.star;
	values[1] = &candidate.lstar;
	values[2] = &candidate.cstar;
	values[3] = &candidate.sfmask;
	values[4] = &candidate.kgsbase;
	values[5] = &candidate.tsc_aux;
	count = VMX_NESTED_SOFTWARE_MSR_COUNT -
	    (tsc_aux_available ? 0U : 1U);
	for (uint32_t i = 0; i < count; i++) {
		error = ops_snapshot.read(arg, indices[i], values[i]);
		if (error != 0)
			return (error);
	}
	*software = candidate;
	return (0);
}

static int
nvmxs_context_valid(const struct vmx_nested_virtual_msr *context)
{

	if (context == NULL ||
	    vmx_nested_capabilities_validate(context->capabilities) != 0 ||
	    context->control == NULL || context->arch == NULL ||
	    context->software == NULL ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    context->capabilities, sizeof(*context->capabilities)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    context->control, sizeof(*context->control)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    context->arch, sizeof(*context->arch)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    context->software, sizeof(*context->software)) ||
	    vmx_nested_state_ranges_overlap(context->capabilities,
	    sizeof(*context->capabilities), context->control,
	    sizeof(*context->control)) ||
	    vmx_nested_state_ranges_overlap(context->capabilities,
	    sizeof(*context->capabilities), context->arch,
	    sizeof(*context->arch)) ||
	    vmx_nested_state_ranges_overlap(context->capabilities,
	    sizeof(*context->capabilities), context->software,
	    sizeof(*context->software)) ||
	    vmx_nested_state_ranges_overlap(context->control,
	    sizeof(*context->control), context->arch, sizeof(*context->arch)) ||
	    vmx_nested_state_ranges_overlap(context->control,
	    sizeof(*context->control), context->software,
	    sizeof(*context->software)) ||
	    vmx_nested_state_ranges_overlap(context->arch,
	    sizeof(*context->arch), context->software,
	    sizeof(*context->software)))
		return (EINVAL);
	return (0);
}

static bool
nvmxs_output_aliases(const struct vmx_nested_virtual_msr *context,
    const void *output, size_t output_length)
{

	return (vmx_nested_state_ranges_overlap(output, output_length, context,
	    sizeof(*context)) || vmx_nested_state_ranges_overlap(output,
	    output_length, context->capabilities, sizeof(*context->capabilities)) ||
	    vmx_nested_state_ranges_overlap(output, output_length, context->control,
	    sizeof(*context->control)) || vmx_nested_state_ranges_overlap(output,
	    output_length, context->arch, sizeof(*context->arch)) ||
	    vmx_nested_state_ranges_overlap(output, output_length, context->software,
	    sizeof(*context->software)));
}

static int
nvmxs_index_supported(const struct vmx_nested_virtual_msr *context,
    uint32_t index, bool write)
{

	switch (index) {
	case NVMXS_MSR_SYSENTER_CS:
	case NVMXS_MSR_SYSENTER_ESP:
	case NVMXS_MSR_SYSENTER_EIP:
	case NVMXS_MSR_DEBUGCTL:
	case NVMXS_MSR_PAT:
	case NVMXS_MSR_EFER:
		return (0);
	case NVMXS_MSR_FS_BASE:
	case NVMXS_MSR_GS_BASE:
		return (write ? ENOTSUP : 0);
	case NVMXS_MSR_STAR:
	case NVMXS_MSR_LSTAR:
	case NVMXS_MSR_CSTAR:
	case NVMXS_MSR_SFMASK:
	case NVMXS_MSR_KGSBASE:
		return (context->syscall_available ? 0 : ENOTSUP);
	case NVMXS_MSR_TSC_AUX:
		return (context->tsc_aux_available ? 0 : ENOTSUP);
	default:
		return (ENOTSUP);
	}
}

static int
nvmxs_value_valid(const struct vmx_nested_virtual_msr *context,
    uint32_t index, uint64_t value)
{
	uint64_t old_efer;
	int error;

	error = nvmxs_index_supported(context, index, true);
	if (error != 0)
		return (error);
	switch (index) {
	case NVMXS_MSR_SYSENTER_CS:
		/*
		 * Bits 63:32 are architecturally ignored by WRMSR.  Preserve
		 * bits 31:16 even though SYSENTER itself does not use them.
		 */
		return (0);
	case NVMXS_MSR_SFMASK:
		return ((value >> 32) == 0 ? 0 : EINVAL);
	case NVMXS_MSR_TSC_AUX:
		return (vmx_nested_tsc_aux_value_validate(value));
	case NVMXS_MSR_SYSENTER_ESP:
	case NVMXS_MSR_SYSENTER_EIP:
	case NVMXS_MSR_LSTAR:
	case NVMXS_MSR_CSTAR:
	case NVMXS_MSR_KGSBASE:
		return (vmx_nested_canonical_address(value,
		    context->capabilities->linear_address_width) ? 0 : EINVAL);
	case NVMXS_MSR_DEBUGCTL:
		return ((value & ~context->capabilities->debugctl_allowed) == 0 ?
		    0 : EINVAL);
	case NVMXS_MSR_PAT:
		return (vmx_nested_pat_valid(value) ? 0 : EINVAL);
	case NVMXS_MSR_EFER:
		old_efer = context->control->efer;
		if ((value & ~NVMXS_EFER_VALID) != 0 ||
		    ((context->control->cr0 & NVMXS_CR0_PG) != 0 &&
		    ((value ^ old_efer) & NVMXS_EFER_LME) != 0))
			return (EINVAL);
		return (0);
	case NVMXS_MSR_STAR:
		return (0);
	default:
		return (ENOTSUP);
	}
}

int
vmx_nested_virtual_msr_validate_write(void *arg, uint32_t index,
    uint64_t value, bool in_smm)
{
	struct vmx_nested_virtual_msr *context;

	context = arg;
	if (nvmxs_context_valid(context) != 0 ||
	    context->arch->in_smm != in_smm)
		return (EINVAL);
	return (nvmxs_value_valid(context, index, value));
}

int
vmx_nested_virtual_msr_validate_read(void *arg, uint32_t index, bool in_smm)
{
	struct vmx_nested_virtual_msr *context;

	context = arg;
	if (nvmxs_context_valid(context) != 0 ||
	    context->arch->in_smm != in_smm)
		return (EINVAL);
	return (nvmxs_index_supported(context, index, false));
}

int
vmx_nested_virtual_msr_read(void *arg, uint32_t index, uint64_t *value)
{
	struct vmx_nested_virtual_msr *context;

	context = arg;
	if (value == NULL || nvmxs_context_valid(context) != 0 ||
	    nvmxs_output_aliases(context, value, sizeof(*value)) ||
	    nvmxs_index_supported(context, index, false) != 0)
		return (EINVAL);
	switch (index) {
	case NVMXS_MSR_SYSENTER_CS:
		*value = context->control->sysenter_cs;
		break;
	case NVMXS_MSR_SYSENTER_ESP:
		*value = context->control->sysenter_esp;
		break;
	case NVMXS_MSR_SYSENTER_EIP:
		*value = context->control->sysenter_eip;
		break;
	case NVMXS_MSR_DEBUGCTL:
		*value = context->arch->debugctl;
		break;
	case NVMXS_MSR_PAT:
		*value = context->control->pat;
		break;
	case NVMXS_MSR_EFER:
		*value = context->control->efer;
		break;
	case NVMXS_MSR_FS_BASE:
		*value = context->arch->segment[
		    VMX_NESTED_GUEST_FS].base;
		break;
	case NVMXS_MSR_GS_BASE:
		*value = context->arch->segment[
		    VMX_NESTED_GUEST_GS].base;
		break;
	case NVMXS_MSR_STAR:
		*value = context->software->star;
		break;
	case NVMXS_MSR_LSTAR:
		*value = context->software->lstar;
		break;
	case NVMXS_MSR_CSTAR:
		*value = context->software->cstar;
		break;
	case NVMXS_MSR_SFMASK:
		*value = context->software->sfmask;
		break;
	case NVMXS_MSR_KGSBASE:
		*value = context->software->kgsbase;
		break;
	case NVMXS_MSR_TSC_AUX:
		*value = context->software->tsc_aux;
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

int
vmx_nested_virtual_msr_write(void *arg, uint32_t index, uint64_t value)
{
	struct vmx_nested_virtual_msr *context;

	context = arg;
	if (nvmxs_context_valid(context) != 0 ||
	    nvmxs_value_valid(context, index, value) != 0)
		return (EINVAL);
	switch (index) {
	case NVMXS_MSR_SYSENTER_CS:
		context->control->sysenter_cs = (uint32_t)value;
		break;
	case NVMXS_MSR_SYSENTER_ESP:
		context->control->sysenter_esp = value;
		break;
	case NVMXS_MSR_SYSENTER_EIP:
		context->control->sysenter_eip = value;
		break;
	case NVMXS_MSR_DEBUGCTL:
		context->arch->debugctl = value;
		break;
	case NVMXS_MSR_PAT:
		context->control->pat = value;
		break;
	case NVMXS_MSR_EFER:
		/*
		 * WRMSR cannot modify IA32_EFER.LMA.  Intel specifies the same
		 * ignored-bit behavior for VM-entry MSR loading.
		 */
		context->control->efer =
		    (value & ~NVMXS_EFER_LMA) |
		    (context->control->efer & NVMXS_EFER_LMA);
		break;
	case NVMXS_MSR_STAR:
		context->software->star = value;
		break;
	case NVMXS_MSR_LSTAR:
		context->software->lstar = value;
		break;
	case NVMXS_MSR_CSTAR:
		context->software->cstar = value;
		break;
	case NVMXS_MSR_SFMASK:
		context->software->sfmask = value;
		break;
	case NVMXS_MSR_KGSBASE:
		context->software->kgsbase = value;
		break;
	case NVMXS_MSR_TSC_AUX:
		context->software->tsc_aux = value;
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

static const struct vmx_nested_msr_apply_ops nvmxs_apply_ops = {
	.read = vmx_nested_virtual_msr_read,
	.write = vmx_nested_virtual_msr_write,
};

const struct vmx_nested_msr_apply_ops *
vmx_nested_virtual_msr_apply_ops(void)
{

	return (&nvmxs_apply_ops);
}
