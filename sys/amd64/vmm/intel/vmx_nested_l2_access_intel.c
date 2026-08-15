/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#include <machine/vmm.h>

#include "vmx_nested_l2_access.h"
#include "vmx_nested_l2_access_intel.h"
#include "vmx_nested_state_range.h"

static int
nvmxl2i_scalar_for_reg(int reg, enum vmx_nested_l2_scalar *scalar)
{

	switch (reg) {
	case VM_REG_GUEST_CR0:
		*scalar = VMX_NESTED_L2_CR0;
		break;
	case VM_REG_GUEST_CR3:
		*scalar = VMX_NESTED_L2_CR3;
		break;
	case VM_REG_GUEST_CR4:
		*scalar = VMX_NESTED_L2_CR4;
		break;
	case VM_REG_GUEST_DR7:
		*scalar = VMX_NESTED_L2_DR7;
		break;
	case VM_REG_GUEST_RSP:
		*scalar = VMX_NESTED_L2_RSP;
		break;
	case VM_REG_GUEST_RIP:
		*scalar = VMX_NESTED_L2_RIP;
		break;
	case VM_REG_GUEST_RFLAGS:
		*scalar = VMX_NESTED_L2_RFLAGS;
		break;
	case VM_REG_GUEST_EFER:
		*scalar = VMX_NESTED_L2_EFER;
		break;
	default:
		return (ENOENT);
	}
	return (0);
}

static int
nvmxl2i_segment_for_reg(int reg,
    enum vmx_nested_guest_segment_id *segment)
{

	switch (reg) {
	case VM_REG_GUEST_ES:
		*segment = VMX_NESTED_GUEST_ES;
		break;
	case VM_REG_GUEST_CS:
		*segment = VMX_NESTED_GUEST_CS;
		break;
	case VM_REG_GUEST_SS:
		*segment = VMX_NESTED_GUEST_SS;
		break;
	case VM_REG_GUEST_DS:
		*segment = VMX_NESTED_GUEST_DS;
		break;
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_FS_BASE:
		*segment = VMX_NESTED_GUEST_FS;
		break;
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_GS_BASE:
		*segment = VMX_NESTED_GUEST_GS;
		break;
	case VM_REG_GUEST_TR:
		*segment = VMX_NESTED_GUEST_TR;
		break;
	case VM_REG_GUEST_LDTR:
		*segment = VMX_NESTED_GUEST_LDTR;
		break;
	default:
		return (ENOENT);
	}
	return (0);
}

int
vmx_nested_l2_intel_getreg(struct vmx_nested_l2_portable_state *state,
    int reg, uint64_t *value)
{
	struct vmx_nested_guest_segment segment_value;
	enum vmx_nested_guest_segment_id segment;
	enum vmx_nested_l2_scalar scalar;
	unsigned int index;
	int error;

	if (state == NULL || value == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), value,
	    sizeof(*value)))
		return (EINVAL);
	error = nvmxl2i_scalar_for_reg(reg, &scalar);
	if (error == 0)
		return (vmx_nested_l2_scalar_get(state, scalar, value));
	error = nvmxl2i_segment_for_reg(reg, &segment);
	if (error == 0) {
		error = vmx_nested_l2_segment_get(state, segment,
		    &segment_value);
		if (error == 0)
			*value = reg == VM_REG_GUEST_FS_BASE ||
			    reg == VM_REG_GUEST_GS_BASE ?
			    segment_value.base : segment_value.selector;
		return (error);
	}
	if (reg >= VM_REG_GUEST_PDPTE0 && reg <= VM_REG_GUEST_PDPTE3) {
		index = reg - VM_REG_GUEST_PDPTE0;
		*value = state->pdpte.value[index];
		return (0);
	}
	switch (reg) {
	case VM_REG_GUEST_ENTRY_INST_LENGTH:
		*value = state->entry_instruction_length;
		return (0);
	case VM_REG_GUEST_KGS_BASE:
		*value = state->software_msrs.kgsbase;
		return (0);
	default:
		return (ENOENT);
	}
}

int
vmx_nested_l2_intel_setreg(struct vmx_nested_l2_portable_state *state,
    int reg, uint64_t value)
{
	struct vmx_nested_guest_segment segment_value;
	enum vmx_nested_guest_segment_id segment;
	enum vmx_nested_l2_scalar scalar;
	unsigned int index;
	int error;

	if (state == NULL)
		return (EINVAL);
	error = nvmxl2i_scalar_for_reg(reg, &scalar);
	if (error == 0)
		return (vmx_nested_l2_scalar_set(state, scalar, value));
	error = nvmxl2i_segment_for_reg(reg, &segment);
	if (error == 0) {
		error = vmx_nested_l2_segment_get(state, segment,
		    &segment_value);
		if (error != 0)
			return (error);
		if (reg == VM_REG_GUEST_FS_BASE ||
		    reg == VM_REG_GUEST_GS_BASE)
			segment_value.base = value;
		else {
			if ((value >> 16) != 0)
				return (ERANGE);
			segment_value.selector = (uint16_t)value;
		}
		return (vmx_nested_l2_segment_set(state, segment,
		    &segment_value));
	}
	if (reg >= VM_REG_GUEST_PDPTE0 && reg <= VM_REG_GUEST_PDPTE3) {
		index = reg - VM_REG_GUEST_PDPTE0;
		state->pdpte.value[index] = value;
		return (0);
	}
	switch (reg) {
	case VM_REG_GUEST_ENTRY_INST_LENGTH:
		if ((value >> 32) != 0)
			return (ERANGE);
		state->entry_instruction_length = (uint32_t)value;
		return (0);
	case VM_REG_GUEST_KGS_BASE:
		state->software_msrs.kgsbase = value;
		return (0);
	default:
		return (ENOENT);
	}
}

int
vmx_nested_l2_intel_getdesc(struct vmx_nested_l2_portable_state *state,
    int reg, struct seg_desc *desc)
{
	struct vmx_nested_guest_segment segment_value;
	struct vmx_nested_l2_table_value table_value;
	enum vmx_nested_guest_segment_id segment;
	enum vmx_nested_l2_table table;
	int error;

	if (state == NULL || desc == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), desc,
	    sizeof(*desc)))
		return (EINVAL);
	if (reg == VM_REG_GUEST_GDTR || reg == VM_REG_GUEST_IDTR) {
		table = reg == VM_REG_GUEST_GDTR ?
		    VMX_NESTED_L2_GDTR : VMX_NESTED_L2_IDTR;
		error = vmx_nested_l2_table_get(state, table, &table_value);
		if (error != 0)
			return (error);
		desc->base = table_value.base;
		desc->limit = table_value.limit;
		desc->access = 0;
		return (0);
	}
	error = nvmxl2i_segment_for_reg(reg, &segment);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_segment_get(state, segment, &segment_value);
	if (error != 0)
		return (error);
	desc->base = segment_value.base;
	desc->limit = segment_value.limit;
	desc->access = segment_value.access;
	return (0);
}

int
vmx_nested_l2_intel_setdesc(struct vmx_nested_l2_portable_state *state,
    int reg, const struct seg_desc *desc)
{
	struct vmx_nested_guest_segment segment_value;
	struct vmx_nested_l2_table_value table_value;
	enum vmx_nested_guest_segment_id segment;
	enum vmx_nested_l2_table table;
	int error;

	if (state == NULL || desc == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), desc,
	    sizeof(*desc)))
		return (EINVAL);
	if (reg == VM_REG_GUEST_GDTR || reg == VM_REG_GUEST_IDTR) {
		table = reg == VM_REG_GUEST_GDTR ?
		    VMX_NESTED_L2_GDTR : VMX_NESTED_L2_IDTR;
		table_value.base = desc->base;
		table_value.limit = desc->limit;
		return (vmx_nested_l2_table_set(state, table, &table_value));
	}
	error = nvmxl2i_segment_for_reg(reg, &segment);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_segment_get(state, segment, &segment_value);
	if (error != 0)
		return (error);
	segment_value.base = desc->base;
	segment_value.limit = desc->limit;
	segment_value.access = desc->access;
	return (vmx_nested_l2_segment_set(state, segment, &segment_value));
}
