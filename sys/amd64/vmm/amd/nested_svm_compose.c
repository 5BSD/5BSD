/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <machine/segments.h>
#include <machine/vmm.h>

#include "vmcb.h"
#include "nested_svm_aux.h"
#include "nested_svm_compose.h"
#include "nested_svm_policy.h"

/*
 * Prepare a private hardware VMCB.  The L1 VMCB12 supplies L2 state, but
 * never supplies host physical pointers or the real ASID.  All L2 I/O and
 * MSR accesses use L0-owned all-intercept maps; the exit policy decides
 * later whether L1 requested the individual intercept.
 */
int
svm_nested_vmcb02_compose(struct vmcb *vmcb02, const struct vmcb *vmcb01,
    const struct vmcb *vmcb12, uint64_t npt02_pa, uint64_t iopm_pa,
    uint64_t msrpm_pa, uint32_t asid02)
{
	struct vmcb_ctrl *ctrl;
	const struct vmcb_ctrl *l0, *l1;
	int i;

	if (vmcb02 == NULL || vmcb01 == NULL || vmcb12 == NULL ||
	    vmcb02 == vmcb01 || vmcb02 == vmcb12 ||
	    ((npt02_pa | iopm_pa | msrpm_pa) & PAGE_MASK) != 0 ||
	    npt02_pa == 0 || iopm_pa == 0 || msrpm_pa == 0 || asid02 == 0)
		return (EINVAL);
	l0 = &vmcb01->ctrl;
	l1 = &vmcb12->ctrl;
	for (i = 0; i < nitems(l0->intercept); i++) {
		if (!svm_nested_l0_intercepts_supported(i,
		    l0->intercept[i]))
			return (EOPNOTSUPP);
	}
	bzero(vmcb02, sizeof(*vmcb02));
	bcopy(&vmcb12->state, &vmcb02->state, sizeof(vmcb02->state));
	/* Without NPT12, PAT is shared with L1 rather than loaded from VMCB12. */
	if (!l1->np_enable)
		vmcb02->state.g_pat = vmcb01->state.g_pat;
	/* VMLOAD changes L1's live auxiliary state, not the VMCB12 image. */
	svm_nested_vmcb_aux_copy(vmcb02, vmcb01);
	/* Without L1 LBR virtualization, L2 inherits L1's live LBR MSRs. */
	if (!l1->lbr_virt_en)
		bcopy((const uint8_t *)vmcb01 + VMCB_OFF_DBGCTL,
		    (uint8_t *)vmcb02 + VMCB_OFF_DBGCTL, 0x28);
	ctrl = &vmcb02->ctrl;
	for (i = 0; i < nitems(ctrl->intercept); i++)
		ctrl->intercept[i] = svm_nested_l0_intercepts_for_l2(i,
		    l0->intercept[i]) | l1->intercept[i];
	ctrl->intercept[VMCB_CR_INTCPT] |=
	    svm_nested_cr8_intercept_mask(l1->v_intr_masking != 0);
	ctrl->intercept[VMCB_CTRL1_INTCPT] |=
	    VMCB_INTCPT_IO | VMCB_INTCPT_MSR;
	ctrl->intercept[VMCB_CTRL2_INTCPT] |= VMCB_INTCPT_VMRUN;
	/* Nested CPUID does not advertise either pause-filter facility. */
	ctrl->pause_filthresh = 0;
	ctrl->pause_filcnt = 0;
	ctrl->iopm_base_pa = iopm_pa;
	ctrl->msrpm_base_pa = msrpm_pa;
	ctrl->tsc_offset = l0->tsc_offset + l1->tsc_offset;
	ctrl->asid = asid02;
	ctrl->tlb_ctrl = VMCB_TLB_FLUSH_ALL;
	ctrl->v_tpr = l1->v_tpr;
	ctrl->v_irq = l1->v_irq;
	ctrl->v_intr_prio = l1->v_intr_prio;
	ctrl->v_ign_tpr = l1->v_ign_tpr;
	ctrl->v_intr_masking = 1;
	ctrl->v_intr_vector = l1->v_intr_vector;
	ctrl->intr_shadow = l1->intr_shadow;
	ctrl->eventinj = l1->eventinj;
	ctrl->np_enable = 1;
	ctrl->n_cr3 = npt02_pa;
	ctrl->lbr_virt_en = l0->lbr_virt_en;
	ctrl->vmcb_clean = 0;
	return (0);
}
