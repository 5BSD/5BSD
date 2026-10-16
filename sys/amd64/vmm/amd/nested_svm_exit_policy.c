/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>

#ifdef _KERNEL
#include <sys/systm.h>
#include <machine/segments.h>
#include <machine/vmm.h>
#endif

#include "vmcb.h"
#include "nested_svm_bitmap.h"
#include "nested_svm_exit_policy.h"
#include "nested_svm_policy.h"

enum svm_nested_l2_l0_action
svm_nested_l2_l0_exit_action(uint64_t code)
{

	switch (code) {
	case VMCB_EXIT_INTR:
	case VMCB_EXIT_NMI:
		return (SVM_NESTED_L2_RESUME);
	case VMCB_EXIT_SMI:
	case VMCB_EXIT_INIT:
	case VMCB_EXIT_FERR_FREEZE:
		return (SVM_NESTED_L2_REPORT_L0);
	case VMCB_EXIT_MC:
		return (SVM_NESTED_L2_MACHINE_CHECK);
	case VMCB_EXIT_INVALID:
		/* VMCB12 invalidity is handled before composing VMCB02. */
		return (SVM_NESTED_L2_FAIL_L0);
	default:
		return (SVM_NESTED_L2_ROUTE);
	}
}

void
svm_nested_l2_l0_exit_info(uint64_t code, uint64_t *info1,
    uint64_t *info2)
{

	if (code == VMCB_EXIT_INIT || code == VMCB_EXIT_FERR_FREEZE) {
		/* Neither intercept defines exit-info fields. */
		*info1 = 0;
		*info2 = 0;
		return;
	}
	if (code != VMCB_EXIT_SMI)
		return;
	/*
	 * SMI reports its source in EXITINFO1[1:0].  The I/O detail bits
	 * and EXITINFO2 are undefined unless EXITINFO1[33] is set.
	 */
	if ((*info1 & (UINT64_C(1) << 33)) == 0) {
		*info1 &= 0x3;
		*info2 = 0;
	} else {
		/* EXITINFO1[42], [31:13], and [9:2] are reserved, RAZ. */
		*info1 &= ~((UINT64_C(1) << 42) |
		    (UINT64_C(0x7ffff) << 13) | (UINT64_C(0xff) << 2));
	}
}

enum svm_nested_l0_debug_action
svm_nested_l0_debug_exit(uint64_t code, uint32_t l0_exceptions,
    uint32_t l0_controls, bool stepping, bool single_step_trap)
{

	if (!stepping)
		return (SVM_NESTED_L0_DEBUG_NONE);
	if (code == VMCB_EXIT_DB && single_step_trap &&
	    (l0_exceptions & (1U << 1)) != 0)
		return (SVM_NESTED_L0_DEBUG_STEP);
	if (code == VMCB_EXIT_PUSHF &&
	    (l0_controls & VMCB_INTCPT_PUSHF) != 0)
		return (SVM_NESTED_L0_DEBUG_PUSHF);
	if (code == VMCB_EXIT_POPF &&
	    (l0_controls & VMCB_INTCPT_POPF) != 0)
		return (SVM_NESTED_L0_DEBUG_POPF);
	return (SVM_NESTED_L0_DEBUG_NONE);
}

int
svm_nested_synthetic_exception_prepare(uint32_t l1_exceptions,
    uint64_t eventinj, uint64_t exitintinfo, uint8_t vector,
    bool error_code_valid, uint32_t error_code,
    struct svm_nested_synthetic_exception *result)
{
	struct svm_nested_synthetic_exception prepared;

	if (result == NULL || (vector != 6 && vector != 13 && vector != 30) ||
	    error_code_valid != (vector != 6) ||
	    (vector == 30 && error_code != 1) ||
	    (!error_code_valid && error_code != 0))
		return (EINVAL);
	prepared = (struct svm_nested_synthetic_exception){ 0 };
	if (((eventinj | exitintinfo) & VMCB_EVENTINJ_VALID) != 0) {
		prepared.action = SVM_NESTED_SYNTHETIC_REPLAY;
	} else if ((l1_exceptions & (1U << vector)) != 0) {
		prepared.action = SVM_NESTED_SYNTHETIC_REFLECT;
		prepared.exitcode = 0x40 + vector;
		prepared.exitinfo1 = error_code_valid ? error_code : 0;
	} else {
		prepared.action = SVM_NESTED_SYNTHETIC_INJECT;
		prepared.eventinj = VMCB_EVENTINJ_VALID |
		    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | vector;
		if (error_code_valid)
			prepared.eventinj |= VMCB_EVENTINJ_EC_VALID |
			    ((uint64_t)error_code << 32);
	}
	*result = prepared;
	return (0);
}

int
svm_nested_exit_intercepted(const struct svm_nested_vmcb12_view *view,
    const struct svm_nested_bitmap_reader *reader, uint64_t code,
    uint64_t info1, uint32_t msr, bool *intercept)
{
	uint32_t bit, index;
	uint8_t bytes;

	if (view == NULL || intercept == NULL)
		return (EINVAL);
	*intercept = false;
	if (code < 0x20) {
		index = VMCB_CR_INTCPT;
		bit = (uint32_t)code;
	} else if (code < 0x40) {
		index = VMCB_DR_INTCPT;
		bit = (uint32_t)code - 0x20;
	} else if (code < 0x60) {
		index = VMCB_EXC_INTCPT;
		bit = (uint32_t)code - 0x40;
	} else if (code < 0x80) {
		index = VMCB_CTRL1_INTCPT;
		bit = (uint32_t)code - 0x60;
	} else if (code < 0xa0) {
		index = VMCB_CTRL2_INTCPT;
		bit = (uint32_t)code - 0x80;
	} else {
		return (0);
	}
	if ((view->intercept[index] & (1U << bit)) == 0)
		return (0);
	if (code == VMCB_EXIT_IO) {
		bytes = (info1 >> 4) & 7;
		/* VMCB bitmap base bits 11:0 are ignored by hardware. */
		return (svm_nested_iopm_intercepts(reader,
		    view->iopm_gpa & ~(uint64_t)(SVM_NESTED_PAGE_SIZE - 1),
		    (uint16_t)(info1 >> 16), bytes, intercept));
	}
	if (code == VMCB_EXIT_MSR)
		return (svm_nested_msrpm_intercepts(reader,
		    view->msrpm_gpa & ~(uint64_t)(SVM_NESTED_PAGE_SIZE - 1),
		    msr, info1 != 0, intercept));
	*intercept = true;
	return (0);
}
