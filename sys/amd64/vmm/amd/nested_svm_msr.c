/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#include <machine/specialreg.h>

#include "nested_svm_msr.h"
#include "nested_svm_policy.h"

void
svm_nested_msr_state_init(struct svm_nested_msr_state *state)
{

	if (state == NULL)
		return;
	state->hsave_gpa = 0;
	state->vm_cr = 0;
	state->exposed = false;
	state->svme = false;
}

void
svm_nested_msr_init_signal(struct svm_nested_msr_state *state)
{

	if (state == NULL)
		return;
	/* INIT clears EFER.SVME; VM_CR.LOCK and VM_HSAVE_PA survive INIT. */
	state->svme = false;
	state->vm_cr &= ~VM_CR_R_INIT;
	if ((state->vm_cr & VM_CR_LOCK) == 0)
		state->vm_cr &= ~VM_CR_SVMDIS;
}

int
svm_nested_msr_exposure_set(struct svm_nested_msr_state *state, int value,
    bool busy)
{

	if (state == NULL || (value != 0 && value != 1))
		return (EINVAL);
	if (state->exposed == (value != 0))
		return (0);
	if (busy || state->svme || state->hsave_gpa != 0 || state->vm_cr != 0)
		return (EBUSY);
	state->exposed = value != 0;
	return (0);
}

bool
svm_nested_msr_state_valid(const struct svm_nested_msr_state *state,
    uint8_t width)
{

	if (state == NULL || width < 32 || width >= 64)
		return (false);
	if (!state->exposed)
		return (!state->svme && state->hsave_gpa == 0 &&
		    state->vm_cr == 0);
	if ((state->vm_cr & ~(VM_CR_R_INIT | VM_CR_LOCK | VM_CR_SVMDIS)) != 0 ||
	    (state->svme && (state->vm_cr & VM_CR_SVMDIS) != 0))
		return (false);
	return ((state->hsave_gpa & (SVM_NESTED_PAGE_SIZE - 1)) == 0 &&
	    svm_nested_guest_physical_range_valid(state->hsave_gpa,
	    SVM_NESTED_PAGE_SIZE, width));
}

uint64_t
svm_nested_msr_efer_read(const struct svm_nested_msr_state *state,
    uint64_t physical_efer)
{

	physical_efer &= ~EFER_SVM;
	if (state != NULL && state->exposed && state->svme)
		physical_efer |= EFER_SVM;
	return (physical_efer);
}

bool
svm_nested_msr_efer_write_allowed(const struct svm_nested_msr_state *state,
    uint64_t guest_efer)
{

	return (state != NULL && ((guest_efer & EFER_SVM) == 0 ||
	    (state->exposed && (state->vm_cr & VM_CR_SVMDIS) == 0)));
}

void
svm_nested_msr_efer_import(struct svm_nested_msr_state *state,
    uint64_t guest_efer)
{

	if (state != NULL)
		state->svme = state->exposed && (guest_efer & EFER_SVM) != 0;
}

bool
svm_nested_msr_hsave_write(struct svm_nested_msr_state *state,
    uint64_t guest_pa, uint8_t width)
{

	if (state == NULL || !state->exposed ||
	    (guest_pa & (SVM_NESTED_PAGE_SIZE - 1)) != 0 ||
	    !svm_nested_guest_physical_range_valid(guest_pa,
	    SVM_NESTED_PAGE_SIZE, width))
		return (false);
	state->hsave_gpa = guest_pa;
	return (true);
}

bool
svm_nested_msr_vmcr_write(struct svm_nested_msr_state *state, uint64_t value)
{

	if (state == NULL || !state->exposed ||
	    (value & ~(VM_CR_R_INIT | VM_CR_LOCK | VM_CR_SVMDIS)) != 0 ||
	    ((value & VM_CR_SVMDIS) != 0 && state->svme))
		return (false);
	/* LOCK only suppresses writes to LOCK and SVMDIS, not R_INIT. */
	if ((state->vm_cr & VM_CR_LOCK) != 0)
		state->vm_cr = (state->vm_cr &
		    (VM_CR_LOCK | VM_CR_SVMDIS)) | (value & VM_CR_R_INIT);
	else
		state->vm_cr = value;
	return (true);
}
