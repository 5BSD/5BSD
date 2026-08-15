/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <machine/specialreg.h>

#include "x86.h"

u_int
vm_mtrr_maxphyaddr(u_int host_phys_addr_width)
{

	if (host_phys_addr_width < VMM_MTRR_PHYS_ADDR_WIDTH_MIN)
		return (0);
	return (MIN(host_phys_addr_width, VMM_MTRR_PHYS_ADDR_WIDTH_MAX));
}

static bool
vm_mtrr_type_valid(uint8_t type)
{

	switch (type) {
	case MTRR_UNCACHEABLE:
	case MTRR_WRITE_COMBINING:
	case MTRR_WRITE_THROUGH:
	case MTRR_WRITE_PROTECTED:
	case MTRR_WRITE_BACK:
		return (true);
	default:
		return (false);
	}
}

static bool
vm_mtrr_fixed_valid(uint64_t value)
{
	u_int i;

	for (i = 0; i < sizeof(value); i++) {
		if (!vm_mtrr_type_valid((uint8_t)(value >> (i * 8))))
			return (false);
	}
	return (true);
}

static bool
vm_mtrr_variable_masks(u_int phys_addr_width, uint64_t *base_mask,
    uint64_t *mask_mask)
{
	uint64_t phys_mask;

	if (phys_addr_width < VMM_MTRR_PHYS_ADDR_WIDTH_MIN ||
	    phys_addr_width > VMM_MTRR_PHYS_ADDR_WIDTH_MAX ||
	    base_mask == NULL || mask_mask == NULL)
		return (false);
	phys_mask = (((uint64_t)1 << phys_addr_width) - 1) &
	    ~(uint64_t)0xfff;
	*base_mask = phys_mask | MTRR_PHYSBASE_TYPE;
	*mask_mask = phys_mask | MTRR_PHYSMASK_VALID;
	return (true);
}

bool
vm_mtrr_validate(const struct vm_mtrr *mtrr, u_int phys_addr_width)
{
	uint64_t base_mask, mask_mask;
	u_int i;

	if (mtrr == NULL || !vm_mtrr_variable_masks(phys_addr_width,
	    &base_mask, &mask_mask) ||
	    (mtrr->def_type & ~VMM_MTRR_DEF_MASK) != 0 ||
	    !vm_mtrr_type_valid(mtrr->def_type & MTRR_DEF_TYPE) ||
	    !vm_mtrr_fixed_valid(mtrr->fixed64k))
		return (false);
	for (i = 0; i < nitems(mtrr->fixed16k); i++) {
		if (!vm_mtrr_fixed_valid(mtrr->fixed16k[i]))
			return (false);
	}
	for (i = 0; i < nitems(mtrr->fixed4k); i++) {
		if (!vm_mtrr_fixed_valid(mtrr->fixed4k[i]))
			return (false);
	}
	for (i = 0; i < nitems(mtrr->var); i++) {
		if ((mtrr->var[i].base & ~base_mask) != 0 ||
		    !vm_mtrr_type_valid(mtrr->var[i].base &
		    MTRR_PHYSBASE_TYPE) ||
		    (mtrr->var[i].mask & ~mask_mask) != 0)
			return (false);
	}
	return (true);
}

int
vm_rdmtrr(struct vm_mtrr *mtrr, u_int num, uint64_t *val)
{
	switch (num) {
	case MSR_MTRRcap:
		*val = MTRR_CAP_WC | MTRR_CAP_FIXED | VMM_MTRR_VAR_MAX;
		break;
	case MSR_MTRRdefType:
		*val = mtrr->def_type;
		break;
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
		*val = mtrr->fixed4k[num - MSR_MTRR4kBase];
		break;
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
		*val = mtrr->fixed16k[num - MSR_MTRR16kBase];
		break;
	case MSR_MTRR64kBase:
		*val = mtrr->fixed64k;
		break;
	case MSR_MTRRVarBase ... MSR_MTRRVarBase +
	    (VMM_MTRR_VAR_MAX * 2) - 1: {
		u_int offset = num - MSR_MTRRVarBase;

		if (offset % 2 == 0)
			*val = mtrr->var[offset / 2].base;
		else
			*val = mtrr->var[offset / 2].mask;
		break;
	}
	default:
		return (-1);
	}

	return (0);
}

int
vm_wrmtrr(struct vm_mtrr *mtrr, u_int num, uint64_t val,
    u_int phys_addr_width)
{
	uint64_t base_mask, mask_mask;

	if (mtrr == NULL || !vm_mtrr_variable_masks(phys_addr_width,
	    &base_mask, &mask_mask))
		return (-1);
	switch (num) {
	case MSR_MTRRcap:
		/* MTRRCAP is read only. */
		return (-1);
	case MSR_MTRRdefType:
		if ((val & ~VMM_MTRR_DEF_MASK) != 0 ||
		    !vm_mtrr_type_valid(val & MTRR_DEF_TYPE))
			return (-1);
		mtrr->def_type = val;
		break;
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
		if (!vm_mtrr_fixed_valid(val))
			return (-1);
		mtrr->fixed4k[num - MSR_MTRR4kBase] = val;
		break;
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
		if (!vm_mtrr_fixed_valid(val))
			return (-1);
		mtrr->fixed16k[num - MSR_MTRR16kBase] = val;
		break;
	case MSR_MTRR64kBase:
		if (!vm_mtrr_fixed_valid(val))
			return (-1);
		mtrr->fixed64k = val;
		break;
	case MSR_MTRRVarBase ... MSR_MTRRVarBase +
	    (VMM_MTRR_VAR_MAX * 2) - 1: {
		u_int offset = num - MSR_MTRRVarBase;

		if (offset % 2 == 0) {
			if ((val & ~base_mask) != 0 ||
			    !vm_mtrr_type_valid(val & MTRR_PHYSBASE_TYPE))
				return (-1);
			mtrr->var[offset / 2].base = val;
		} else {
			if ((val & ~mask_mask) != 0)
				return (-1);
			mtrr->var[offset / 2].mask = val;
		}
		break;
	}
	default:
		return (-1);
	}

	return (0);
}
